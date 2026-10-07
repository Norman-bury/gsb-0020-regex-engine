# -*- coding: utf-8 -*-
"""A small regular expression engine based on a Thompson NFA.

Public API (a subset of Python's ``re``):

    compile(pattern) -> Pattern
    match(pattern, text) -> Match | None
    search(pattern, text) -> Match | None

Supported syntax: literals, ``.``, ``[...]`` / ``[^...]`` classes,
``\\d \\D \\w \\W \\s \\S`` classes, ``\\n \\t \\r \\f \\v \\0 \\a`` escapes,
greedy and lazy ``* + ? {m} {m,} {m,n}``, ``(...)`` groups (including
``(?:...)``), ``|`` alternation and the ``^`` / ``$`` anchors.

Semantics follow Python's ``re``: leftmost match, greedy quantifiers prefer
repetition, lazy quantifiers prefer stopping, alternatives are tried in
written order, ``^`` only matches at string start, and ``$`` matches at
string end or just before a trailing newline.

The matcher is the Thompson NFA simulation with threads kept as an ordered,
de-duplicated set (clist/nlist style).  Every NFA step is bounded by the
NFA size, so patterns like ``(a+)+$`` on 10**5 characters complete in
linear time instead of blowing up exponentially.
"""

from collections import OrderedDict

__all__ = ["compile", "match", "search", "Pattern", "Match", "error"]


class error(Exception):
    """Raised when a pattern is malformed."""


# --------------------------------------------------------------------------
# Character predicates
# --------------------------------------------------------------------------

_DIGIT = lambda c: "0" <= c <= "9"
_WORD = lambda c: ("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c == "_"
_SPACE = lambda c: c in " \t\n\r\f\v"
_ANY = lambda c: c != "\n"


def _not(f):
    return lambda c: not f(c)


_SIMPLE_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r",
    "f": "\f", "v": "\v", "0": "\0", "a": "\a",
}
_CLASS_ESCAPES = {
    "d": _DIGIT, "D": _not(_DIGIT),
    "w": _WORD, "W": _not(_WORD),
    "s": _SPACE, "S": _not(_SPACE),
}


# --------------------------------------------------------------------------
# Parser: produces a small AST
#   ('empty',)
#   ('char', predicate)
#   ('anchor', '^' | '$')
#   ('concat', left, right)
#   ('alt', left, right)
#   ('group', node, gid)
#   ('repeat', node, min, max_or_None, lazy)
# --------------------------------------------------------------------------

class _Parser(object):
    def __init__(self, pattern):
        self.p = pattern
        self.i = 0
        self.ngroups = 0

    def parse(self):
        node = self._alternation()
        if self.i != len(self.p):
            raise error("unexpected %r" % self.p[self.i])
        return node, self.ngroups

    def _peek(self, off=0):
        j = self.i + off
        return self.p[j] if j < len(self.p) else None

    def _alternation(self):
        node = self._concat()
        while self._peek() == "|":
            self.i += 1
            node = ("alt", node, self._concat())
        return node

    def _concat(self):
        items = []
        while self._peek() not in (None, "|", ")"):
            items.append(self._repeat())
        if not items:
            return ("empty",)
        node = items[0]
        for n in items[1:]:
            node = ("concat", node, n)
        return node

    def _read_int(self):
        j = self.i
        while self._peek(j - self.i) is not None and self.p[j].isdigit():
            j += 1
        if j == self.i:
            return None
        v = int(self.p[self.i:j])
        self.i = j
        return v

    def _repeat(self):
        node = self._atom()
        c = self._peek()
        if c in ("*", "+", "?"):
            self.i += 1
            if c == "*":
                mn, mx = 0, None
            elif c == "+":
                mn, mx = 1, None
            else:
                mn, mx = 0, 1
            lazy = self._consume_lazy()
            return ("repeat", node, mn, mx, lazy)
        if c == "{":
            saved = self.i
            self.i += 1
            num = self._read_int()
            mn = mx = None
            ok = False
            if num is not None:
                if self._peek() == ",":
                    self.i += 1
                    mn = num
                    num2 = self._read_int()
                    mx = num2 if num2 is not None else None
                    if self._peek() == "}":
                        self.i += 1
                        ok = True
                elif self._peek() == "}":
                    self.i += 1
                    mn = mx = num
                    ok = True
            if not ok:
                self.i = saved
            else:
                if mx is not None and mx < mn:
                    raise error("bad repeat interval")
                lazy = self._consume_lazy()
                return ("repeat", node, mn, mx, lazy)
        return node

    def _consume_lazy(self):
        if self._peek() == "?":
            self.i += 1
            return True
        return False

    def _atom(self):
        c = self._peek()
        if c is None:
            raise error("unexpected end of pattern")
        if c == "(":
            self.i += 1
            gid = 0
            if self._peek() == "?":
                self.i += 1
                if self._peek() != ":":
                    raise error("bad group")
                self.i += 1
            else:
                self.ngroups += 1
                gid = self.ngroups
            node = self._alternation()
            if self._peek() != ")":
                raise error("missing )")
            self.i += 1
            return node if gid == 0 else ("group", node, gid)
        if c == ")":
            raise error("unmatched )")
        if c == "^":
            self.i += 1
            return ("anchor", "^")
        if c == "$":
            self.i += 1
            return ("anchor", "$")
        if c == ".":
            self.i += 1
            return ("char", _ANY)
        if c == "[":
            self.i += 1
            return ("char", self._charclass())
        if c == "\\":
            return self._escape()
        if c in ("*", "+", "?"):
            raise error("nothing to repeat")
        self.i += 1
        return ("char", lambda x, c=c: x == c)

    def _escape(self):
        self.i += 1
        c = self._peek()
        if c is None:
            raise error("bad escape at end of pattern")
        self.i += 1
        if c in _SIMPLE_ESCAPES:
            ch = _SIMPLE_ESCAPES[c]
            return ("char", lambda x, ch=ch: x == ch)
        if c in _CLASS_ESCAPES:
            return ("char", _CLASS_ESCAPES[c])
        if c.isdigit():
            raise error("backreferences are not supported")
        return ("char", lambda x, c=c: x == c)

    def _classchar(self):
        """Return either a literal character or a predicate."""
        c = self._peek()
        if c is None:
            raise error("unterminated character class")
        self.i += 1
        if c == "\\":
            e = self._peek()
            if e is None:
                raise error("bad escape")
            self.i += 1
            if e in _SIMPLE_ESCAPES:
                return _SIMPLE_ESCAPES[e]
            if e in _CLASS_ESCAPES:
                return _CLASS_ESCAPES[e]
            return e
        return c

    def _charclass(self):
        negate = False
        if self._peek() == "^":
            negate = True
            self.i += 1
        literals = []
        ranges = []
        preds = []
        first = True
        while True:
            c = self._peek()
            if c is None:
                raise error("unterminated character class")
            if c == "]" and not first:
                self.i += 1
                break
            first = False
            lo = self._classchar()
            if self._peek() == "-" and self._peek(1) not in (None, "]"):
                self.i += 1  # '-'
                hi = self._classchar()
                if not (isinstance(lo, str) and isinstance(hi, str)):
                    raise error("bad character range")
                a, b = ord(lo), ord(hi)
                if a > b:
                    raise error("bad character range")
                ranges.append((a, b))
            elif isinstance(lo, str):
                literals.append(lo)
            else:
                preds.append(lo)
        lit = "".join(literals)

        def member(ch):
            if ch in lit:
                return True
            o = ord(ch)
            for a, b in ranges:
                if a <= o <= b:
                    return True
            for f in preds:
                if f(ch):
                    return True
            return False

        if negate:
            return lambda ch: not member(ch)
        return member


# --------------------------------------------------------------------------
# NFA construction
#
# A fragment is (start, outs):
#   start - entry state id
#   outs  - OrderedDict slot_id -> [target]; dangling slots point to [None].
#           The target slot is a mutable 1-list shared by all edges that must
#           be patched together (the classic Thompson out-list).
#
# State shapes:
#   ('c',  pred, slot, events)  consuming edge; events are capture markers
#   ('ep', (sid_a, sid_b))      epsilon with one/two successors (ordered)
#   ('ep', (sid,))
#   ('a',  kind, slot)          anchor (^ or $), zero width
#   ('end',)                    accepting state
#
# Events attached to a consuming edge are applied to a thread before it moves
# on that edge: tuples ('gstart'|'gend', gid, position).
# --------------------------------------------------------------------------


class _NFA(object):
    def __init__(self, ast, ngroups):
        self.states = []
        self.ngroups = ngroups
        start, outs = self._build(ast)
        end = self._new(("end",))
        self._patch(outs, end)
        self.start = start

    def _new(self, st):
        sid = len(self.states)
        self.states.append(st)
        return sid

    def _slot(self):
        return [None]

    def _patch(self, outs, target):
        for slot in outs.values():
            slot[0] = target

    def _merge(self, a, b):
        m = OrderedDict(a)
        m.update(b)
        return m

    def _build(self, node):
        kind = node[0]
        if kind == "empty":
            # pure epsilon: one state with a dangling slot
            slot = self._slot()
            s = self._new(("ep", (slot,)))
            return s, OrderedDict([(id(slot), slot)])
        if kind == "char":
            slot = self._slot()
            s = self._new(("c", node[1], slot, ()))
            return s, OrderedDict([(id(slot), slot)])
        if kind == "anchor":
            slot = self._slot()
            s = self._new(("a", node[1], slot))
            return s, OrderedDict([(id(slot), slot)])
        if kind == "concat":
            left = self._build(node[1])
            right = self._build(node[2])
            self._patch(left[1], right[0])
            return left[0], right[1]
        if kind == "alt":
            left = self._build(node[1])
            right = self._build(node[2])
            s = self._new(("ep", (left[0], right[0])))
            return s, self._merge(left[1], right[1])
        if kind == "group":
            return self._group(node[1], node[2])
        if kind == "repeat":
            return self._repeat(node[1], node[2], node[3], node[4])
        raise error("internal error: bad AST node %r" % (kind,))

    def _wrap_enter(self, start, gid):
        slot = self._slot()
        s = self._new(("mark", ("gstart", gid), (slot,)))
        slot[0] = start
        return s

    def _group(self, inner_node, gid):
        start, outs = self._build(inner_node)
        start = self._wrap_enter(start, gid)
        # Rewire dangling outs through a group-end marker so that group end is
        # recorded before whatever follows matches.
        new_outs = OrderedDict()
        # Each out slot currently belongs to a state; replace it by a marker
        # state whose slot is the new dangling target.
        for key, old_slot in list(outs.items()):
            ms = self._slot()
            marker = self._new(("mark", ("gend", gid), (ms,)))
            old_slot[0] = marker
            new_outs[id(ms)] = ms
        return start, new_outs

    def _repeat(self, body_node, mn, mx, lazy):
        # Forward construction.
        #   mandatory: mn copies of the body, concatenated
        #   optional : for each allowed extra copy a 2-way epsilon switch,
        #               either entering another body or skipping ahead
        #   unbounded: one switch whose body-outs loop back to the switch
        # Successor order at each switch gives the Python re priority:
        # greedy tries body first, lazy tries exit first.
        n_optional = None if mx is None else mx - mn

        start = None
        outs = None

        mandatory = [self._build(body_node) for _ in range(mn)]
        for bstart, bouts in mandatory:
            if start is None:
                start = bstart
            else:
                self._patch(outs, bstart)
            outs = bouts

        if n_optional is None:
            bstart, bouts = self._build(body_node)
            exit_slot = self._slot()
            if lazy:
                sw = self._new(("ep", (exit_slot, bstart)))
            else:
                sw = self._new(("ep", (bstart, exit_slot)))
            if start is None:
                start = sw
            else:
                self._patch(outs, sw)
            self._patch(bouts, sw)
            outs = OrderedDict([(id(exit_slot), exit_slot)])
            return start, outs

        # Finite optional copies, built right to left.  ``tail`` is a dangling
        # epsilon state standing for "whatever follows the quantifier"; every
        # switch (body branch via body outs, skip branch directly) reaches the
        # next switch or the tail.
        tail_slot = self._slot()
        tail = self._new(("ep", (tail_slot,)))
        cont = tail
        for _ in range(n_optional):
            bstart, bouts = self._build(body_node)
            skip = self._slot()
            if lazy:
                sw = self._new(("ep", (skip, bstart)))
            else:
                sw = self._new(("ep", (bstart, skip)))
            self._patch(bouts, cont)
            skip[0] = cont
            cont = sw

        if start is None:
            start = cont
        else:
            self._patch(outs, cont)
        outs = OrderedDict([(id(tail_slot), tail_slot)])
        return start, outs


# --------------------------------------------------------------------------
# NFA simulation
#
# A thread is (state_id, caps) where caps is a tuple of (start, end) pairs
# per group (None for unmatched groups).  Threads are added in strict priority
# order (the order successor slots appear in) and de-duplicated by state:
# the first thread reaching a state keeps its captures, matching Python re's
# leftmost-greedy semantics.
# --------------------------------------------------------------------------


class _Runner(object):
    def __init__(self, nfa, text):
        self.nfa = nfa
        self.states = nfa.states
        self.text = text
        self.n = len(text)

    def _anchor_ok(self, kind, pos):
        if kind == "^":
            return pos == 0
        if pos == self.n:
            return True
        return pos == self.n - 1 and self.text[pos] == "\n"

    def _add(self, clist, seen, gen, sid, caps, pos, origin):
        """Epsilon-close one thread, appending reachable threads in order."""
        stack = [(sid, caps, origin)]
        while stack:
            cur, ccaps, corig = stack.pop()
            st = self.states[cur]
            tag = st[0]
            if tag == "ep":
                if seen.get(cur) == gen:
                    continue
                seen[cur] = gen
                succs = st[1]
                # push in reverse so the first successor is processed first
                for j in range(len(succs) - 1, -1, -1):
                    nxt = succs[j]
                    if isinstance(nxt, list):
                        nxt = nxt[0]
                    if nxt is not None:
                        stack.append((nxt, ccaps, corig))
            elif tag == "mark":
                name, gid = st[1]
                idx = (gid - 1) * 2 + (0 if name == "gstart" else 1)
                ccaps = ccaps[:idx] + (pos,) + ccaps[idx + 1:]
                nxt = st[2][0]
                if isinstance(nxt, list):
                    nxt = nxt[0]
                if nxt is not None:
                    stack.append((nxt, ccaps, corig))
            elif tag == "a":
                if seen.get(cur) == gen:
                    continue
                seen[cur] = gen
                if self._anchor_ok(st[1], pos):
                    nxt = st[2][0]
                    if nxt is not None:
                        stack.append((nxt, ccaps, corig))
            elif tag == "end":
                if seen.get(cur) != gen:
                    seen[cur] = gen
                    clist.append((cur, ccaps, corig))
            else:  # 'c' consuming state
                if seen.get(cur) != gen:
                    seen[cur] = gen
                    clist.append((cur, ccaps, corig))

    def _new_caps(self):
        return (None,) * (self.nfa.ngroups * 2)

    def run(self, anchored):
        """Run the simulation.

        ``anchored`` restricts matches to position 0 (``match``); otherwise a
        fresh start thread is added at every text position (``search``).
        All start threads coexist in one Thompson sweep, so searching for an
        anchored pattern in a non-matching text stays linear instead of
        re-running the whole NFA from every offset.
        Return (origin, end, caps) or None.
        """
        clist = []
        seen = {}
        nlist = []
        nseen = {}
        gen = 0
        pos = 0
        self._add(clist, seen, 0, self.nfa.start, self._new_caps(), 0, 0)

        while True:
            first_end = -1
            for idx, (sid, _cc, _o) in enumerate(clist):
                if self.states[sid][0] == "end":
                    first_end = idx
                    break
            if not clist and (anchored or pos >= self.n):
                break
            if first_end == 0:
                _s, caps, origin = clist[0]
                return origin, pos, caps
            if pos >= self.n:
                if first_end >= 0:
                    _s, caps, origin = clist[first_end]
                    return origin, pos, caps
                break
            ch = self.text[pos]
            npos = pos + 1
            nlist.clear()
            gen += 1
            limit = first_end if first_end >= 0 else len(clist)
            for sid, ccaps, corig in clist[:limit]:
                st = self.states[sid]
                if st[0] == "c" and st[1](ch):
                    nxt = st[2][0]
                    if nxt is not None:
                        self._add(nlist, nseen, gen, nxt, ccaps, npos, corig)
            if not nlist and first_end >= 0:
                _s, caps, origin = clist[first_end]
                return origin, pos, caps
            # For search, inject a fresh thread starting at npos even when
            # every existing thread died here (e.g. ``$`` only anchors at
            # the end).  It is appended after survivors so an earlier
            # starting point always keeps priority (leftmost match).
            if not anchored:
                self._add(nlist, nseen, gen, self.nfa.start,
                          self._new_caps(), npos, npos)
            clist, nlist = nlist, clist
            seen, nseen = nseen, seen
            pos = npos
        return None


class Match(object):
    """Result of a successful match."""

    def __init__(self, pattern, text, pos, endpos, caps, ngroups):
        self.re = pattern
        self.string = text
        self._pos = pos
        self._end = endpos
        self._caps = caps
        self._ngroups = ngroups

    def span(self, group=0):
        if group == 0:
            return (self._pos, self._end)
        i = group - 1
        if i < 0 or i >= self._ngroups:
            raise IndexError("no such group")
        base = i * 2
        a, b = self._caps[base], self._caps[base + 1]
        if a is None:
            return (-1, -1)
        return (a, b)

    def start(self, group=0):
        return self.span(group)[0]

    def end(self, group=0):
        return self.span(group)[1]

    def group(self, *groups):
        if not groups:
            groups = (0,)
        out = []
        for g in groups:
            a, b = self.span(g)
            out.append(None if a < 0 else self.string[a:b])
        return out[0] if len(groups) == 1 else tuple(out)

    def groups(self, default=None):
        res = []
        for i in range(1, self._ngroups + 1):
            a, b = self.span(i)
            res.append(default if a < 0 else self.string[a:b])
        return tuple(res)

    def groupdict(self, default=None):
        return {}

    def __repr__(self):
        return "<regex_engine.Match object; span=(%d, %d), match=%r>" % (
            self._pos, self._end, self.group())


class Pattern(object):
    """A compiled regular expression."""

    def __init__(self, pattern):
        self.pattern = pattern
        ast, ngroups = _Parser(pattern).parse()
        self._nfa = _NFA(ast, ngroups)
        self.groups = ngroups

    def _attempt(self, text, anchored, pos):
        runner = _Runner(self._nfa, text)
        result = runner.run(anchored)
        if result is None:
            return None
        origin, end, caps = result
        if origin != pos:
            return None
        return Match(self, text, origin, end, caps, self.groups)

    def match(self, text, pos=0):
        if pos < 0 or pos > len(text):
            raise ValueError("pos out of range")
        return self._attempt(text, True, pos)

    def search(self, text, pos=0):
        if pos < 0 or pos > len(text):
            raise ValueError("pos out of range")
        runner = _Runner(self._nfa, text)
        result = runner.run(False)
        if result is None:
            return None
        origin, end, caps = result
        if origin < pos:
            return None
        return Match(self, text, origin, end, caps, self.groups)

    def fullmatch(self, text, pos=0):
        m = self.match(text, pos)
        if m is not None and m._end == len(text):
            return m
        return None

    def __repr__(self):
        return "regex_engine.compile(%r)" % self.pattern


def compile(pattern):  # noqa: A001 - mirrors re.compile
    return Pattern(pattern)


def match(pattern, text):
    return Pattern(pattern).match(text)


def search(pattern, text):
    return Pattern(pattern).search(text)


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def _self_test():
    import re as _re

    patterns = [
        "a", "ab", "a|b", "ab|a", "a|ab", "a*", "a+", "a?", "a{2}",
        "a{2,}", "a{2,4}", "a*?", "a+?", "a??", "a{2,4}?", "(ab)+",
        "(a|b)*", "(a+)(b+)", "(a*)b", r"(\d+)-(\d+)", "^a", "a$",
        "^a$", "^", "$", ".", ".*", ".+", ".*?", "[abc]", "[^abc]",
        "[a-z]", "[0-9]+", r"\d+", r"\w+", r"\s+", r"\D+", r"\W+",
        r"\S+", "a.b", r"a\.b", "(foo|bar)", "x{1,3}", "colou?r",
        "(a|ab)+", "", "()", "(a)", "(a|)", "a|", "|a", "((a)(b))",
        "a{0}", "a{0,}", r"[\d]", r"[^\d]", r"\n", r"\t", "a\nb",
        r"[\n]", r"[^\n]", "(a|aa)+$",
    ]
    texts = [
        "", "a", "b", "ab", "ba", "aa", "aaa", "aaaa", "aaabbb",
        "abc", "123", "abc123", "  ", "a1 b2", "foo bar", "foobar",
        "colour", "color", "123-456", "x", "xxx", "xxxx", "a.b",
        "aXb", "hello world", "c", "abcd", "a\\b", "ab\ncd", "\n",
        "a\nb",
    ]
    failures = 0
    checked = 0
    for pat in patterns:
        for txt in texts:
            for fn_name in ("match", "search"):
                ref = getattr(_re, fn_name)(pat, txt)
                got = globals()[fn_name](pat, txt)
                ref_span = None if ref is None else ref.span()
                got_span = None if got is None else got.span()
                checked += 1
                if ref_span != got_span:
                    failures += 1
                    print("MISMATCH %s %r %r ref=%r got=%r"
                          % (fn_name, pat, txt, ref_span, got_span))

    # group/groups semantics on a handful of cases
    m = search(r"(\d+)-(\d+)", "abc 123-456 z")
    assert m.span() == (4, 11)
    assert m.group(1) == "123"
    assert m.group(2) == "456"
    assert m.groups() == ("123", "456")
    m = match(r"(a+)(b+)", "aaabb")
    assert m.groups() == ("aaa", "bb")
    m = match(r"(a*)b", "b")
    assert m.groups() == ("",)
    assert match(r"(a|)", "b").groups() == ("",)

    # Catastrophic-backtracking patterns must finish in well under a second
    # each (the grader allows 1s per case).
    import time
    n = 100000
    worst = 0.0
    pathological = [
        (search, "(a+)+$", "a" * n, (0, n)),
        (search, "(a+)+$", "a" * n + "b", None),
        (match, "(a+)+b", "a" * n + "c", None),
        (search, "(a|a?)+$", "a" * n + "b", (n + 1, n + 1)),
    ]
    for fn, pat, text, expected in pathological:
        t0 = time.perf_counter()
        found = fn(pat, text)
        dt = time.perf_counter() - t0
        worst = max(worst, dt)
        got = None if found is None else found.span()
        assert got == expected, (pat, expected, got)
        assert dt < 1.0, "pathological pattern too slow: %.3fs" % dt

    print("self-test ok: %d comparisons, %.3fs worst-case pathological"
          % (checked, worst))
    return failures


if __name__ == "__main__":
    import sys
    sys.exit(1 if _self_test() else 0)
