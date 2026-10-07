#!#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Regular expression engine: Thompson NFA executed by a Pike VM.

Public API (subset of Python's re):
    compile(pattern) -> Pattern (.match/.search)
    match(pattern, text) -> Match | None
    search(pattern, text) -> Match | None

Syntax: literals, ., [...] / [^...], \d \D \w \W \s \S, \n \t \r,
* + ? {m} {m,} {m,n} with lazy variants, (...) groups, | alternation,
^ and $ anchors.

The Pike VM keeps a thread set per position; threads that reach an already
occupied NFA state are merged (first thread wins), giving O(n * states) time
and avoiding catastrophic backtracking.
"""

import sys

WORD_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
SPACE_CHARS = frozenset(" \t\n\r\v\f")
DIGIT_CHARS = frozenset("0123456789")


class _Node(object):
    __slots__ = ("kind", "out", "out2", "ch", "chars", "cats", "neg",
                 "gid", "close", "anchor", "lazy", "num")

    def __init__(self, kind):
        self.kind = kind       # 'c' char, 'cl' class, '.' any, 'e' epsilon,
                               # 's' split, 'm' match, 'g' group eps, 'a' anchor
        self.out = None
        self.out2 = None
        self.ch = None
        self.chars = None      # frozenset of literal chars for 'cl'
        self.cats = ""         # category letters subset of dDwWsS for 'cl'
        self.neg = False
        self.gid = -1          # group id for 'g'
        self.close = False     # 'g' marks group close when True
        self.anchor = None     # '^' or '$' for 'a'
        self.lazy = False      # split preference
        self.num = -1


class _Frag(object):
    __slots__ = ("start", "ends")

    def __init__(self, start, ends):
        self.start = start
        self.ends = ends  # list of (node, slot), slot 1 -> out, 2 -> out2


def _patch(ends, target):
    for node, slot in ends:
        if slot == 1:
            node.out = target
        else:
            node.out2 = target


def _link(frag, cont):
    _patch(frag.ends, cont)
    return frag.start


class _Parser(object):
    def __init__(self, pattern):
        self.s = pattern
        self.i = 0
        self.ng = 1  # group 0 is the whole match

    def error(self, msg):
        raise ValueError("regex error: %s" % msg)

    # entry
    def parse(self):
        start = self.alt()
        if self.i != len(self.s):
            self.error("unexpected %r" % self.s[self.i])
        # wrap whole-match group: op -> alt... -> cl -> match
        cl = _Node('g'); cl.gid = 0; cl.close = True
        match = _Node('m')
        cl.out = match
        _patch(start.ends, cl)
        op = _Node('g'); op.gid = 0; op.out = start.start
        return op, self.ng

    def alt(self):
        frag = self.concat()
        splits = []
        while self.i < len(self.s) and self.s[self.i] == '|':
            self.i += 1
            splits.append(frag)
            frag = self.concat()
        if not splits:
            return frag
        # chain splits left-to-right, each split prefers its left branch
        result = frag
        for left in reversed(splits):
            sp = _Node('s')
            sp.out = left.start
            sp.out2 = result.start
            result = _Frag(sp, left.ends + result.ends)
        return result

    def concat(self):
        frag = None
        while self.i < len(self.s) and self.s[self.i] not in ')|':
            atom = self.quant()
            if frag is None:
                frag = atom
            else:
                _patch(frag.ends, atom.start)
                frag = _Frag(frag.start, atom.ends)
        if frag is None:
            e = _Node('e')
            frag = _Frag(e, [(e, 1)])
        return frag

    def quant(self):
        frag = self.atom()
        while self.i < len(self.s):
            c = self.s[self.i]
            if c == '*':
                self.i += 1
                frag, splits = self._rep(frag, 0, None)
            elif c == '+':
                self.i += 1
                frag, splits = self._rep(frag, 1, None)
            elif c == '?':
                self.i += 1
                frag, splits = self._rep(frag, 0, 1)
            elif c == '{':
                m, n, ok = self._brace()
                if not ok:
                    break
                frag, splits = self._rep(frag, m, n)
            else:
                break
            if self.i < len(self.s) and self.s[self.i] == '?':
                self.i += 1
                for sp in splits:
                    sp.lazy = True
        return frag

    def _brace(self):
        j = self.i + 1
        k = j
        while k < len(self.s) and self.s[k].isdigit():
            k += 1
        if k == j:
            return 0, 0, False
        m = int(self.s[j:k])
        if k < len(self.s) and self.s[k] == '}':
            self.i = k + 1
            return m, m, True
        if k < len(self.s) and self.s[k] == ',':
            t = k + 1
            u = t
            while u < len(self.s) and self.s[u].isdigit():
                u += 1
            if u < len(self.s) and self.s[u] == '}':
                n = None if u == t else int(self.s[t:u])
                self.i = u + 1
                return m, n, True
        return 0, 0, False

    def _rep(self, frag, mn, mx):
        """Repeat a body. Fixed minimum copies are unrolled; the extra
        unbounded or bounded part uses loop splits. Every copy is a distinct
        subgraph (built with _dup), so thread-state keys never collide.

        Returns (fragment, controlling splits).
        """
        splits = []
        head = None
        ends = None
        for _ in range(mn):
            body = _dup(frag)
            if head is None:
                head = body.start
                ends = list(body.ends)
            else:
                _patch(ends, body.start)
                ends = list(body.ends)
        if mx is None:
            body = _dup(frag)
            sp = _Node('s')
            if mn == 0:
                e = _Node('e')
                head = e
                ends = [(e, 1)]
            _patch(ends, sp)
            sp.out = body.start
            _patch(body.ends, sp)
            splits.append(sp)
            return _Frag(head, [(sp, 2)]), splits
        extra = mx - mn
        if mn == 0 and extra == 0:
            e = _Node('e')
            return _Frag(e, [(e, 1)]), splits
        if mn == 0:
            e = _Node('e')
            head = e
            ends = [(e, 1)]
        for _ in range(extra):
            body = _dup(frag)
            sp = _Node('s')
            sp.out = body.start
            _patch(ends, sp)
            ends = list(body.ends) + [(sp, 2)]
            splits.append(sp)
        return _Frag(head, ends), splits

    def atom(self):
        c = self.s[self.i]
        if c == '(':
            self.i += 1
            gid = self.ng
            self.ng += 1
            sub = self.alt()
            if self.i >= len(self.s) or self.s[self.i] != ')':
                self.error("missing )")
            self.i += 1
            cl = _Node('g'); cl.gid = gid; cl.close = True
            _patch(sub.ends, cl)
            op = _Node('g'); op.gid = gid; op.out = sub.start
            return _Frag(op, [(cl, 1)])
        if c == '[':
            return self.charclass()
        if c == '.':
            self.i += 1
            n = _Node('.')
            return _Frag(n, [(n, 1)])
        if c == '^':
            self.i += 1
            n = _Node('a'); n.anchor = '^'
            return _Frag(n, [(n, 1)])
        if c == '$':
            self.i += 1
            n = _Node('a'); n.anchor = '$'
            return _Frag(n, [(n, 1)])
        if c == '\\':
            self.i += 1
            if self.i >= len(self.s):
                self.error("trailing backslash")
            return self.escaped()
        if c in '*+?)' or c == '{' or c == '}':
            self.error("unexpected %r" % c)
        self.i += 1
        n = _Node('c'); n.ch = c
        return _Frag(n, [(n, 1)])

    def escaped(self):
        e = self.s[self.i]
        self.i += 1
        if e in 'dDwWsS':
            n = _Node('cl')
            n.chars = frozenset()
            n.cats = e
            n.neg = False
            return _Frag(n, [(n, 1)])
        if e == 'n':
            ch = '\n'
        elif e == 't':
            ch = '\t'
        elif e == 'r':
            ch = '\r'
        else:
            ch = e
        n = _Node('c'); n.ch = ch
        return _Frag(n, [(n, 1)])

    def charclass(self):
        self.i += 1  # [
        neg = False
        if self.i < len(self.s) and self.s[self.i] == '^':
            neg = True
            self.i += 1
        chars = set()
        cats = []
        first = True
        while self.i < len(self.s) and (self.s[self.i] != ']' or first):
            first = False
            self.class_item(chars, cats)
        if self.i >= len(self.s):
            self.error("unterminated character class")
        self.i += 1  # ]
        n = _Node('cl')
        n.chars = frozenset(chars)
        n.cats = ''.join(cats)
        n.neg = neg
        return _Frag(n, [(n, 1)])

    def class_char(self):
        """Read one char/category inside a class. Returns str or ('cat', x)."""
        c = self.s[self.i]
        if c == '\\':
            self.i += 1
            if self.i >= len(self.s):
                self.error("trailing backslash in class")
            e = self.s[self.i]
            self.i += 1
            if e in 'dDwWsS':
                return ('cat', e)
            if e == 'n':
                return '\n'
            if e == 't':
                return '\t'
            if e == 'r':
                return '\r'
            return e
        self.i += 1
        return c

    def class_item(self, chars, cats):
        lo = self.class_char()
        if (self.i + 1 < len(self.s) and self.s[self.i] == '-'
                and self.s[self.i + 1] != ']'):
            self.i += 1  # -
            hi = self.class_char()
            if isinstance(lo, tuple) or isinstance(hi, tuple):
                self.add_class_value(lo, chars, cats)
                chars.add('-')
                self.add_class_value(hi, chars, cats)
            else:
                a = ord(lo)
                b = ord(hi)
                if a > b:
                    a, b = b, a
                for code in range(a, b + 1):
                    chars.add(chr(code))
        else:
            self.add_class_value(lo, chars, cats)

    @staticmethod
    def add_class_value(v, chars, cats):
        if isinstance(v, tuple):
            cats.append(v[1])
        else:
            chars.add(v)


def _dup(frag):
    """Deep-copy a fragment preserving internal cycles.

    frag.ends names nodes together with the *outgoing* slot that is dangling
    (1 = out, 2 = out2). That outgoing edge is copied as None; everything else
    is copied recursively.
    """
    dang = {}
    for node, slot in frag.ends:
        dang.setdefault(id(node), set()).add(slot)
    memo = {}

    def fresh(nd):
        c = _Node(nd.kind)
        c.ch = nd.ch
        c.chars = nd.chars
        c.cats = nd.cats
        c.neg = nd.neg
        c.gid = nd.gid
        c.close = nd.close
        c.anchor = nd.anchor
        c.lazy = nd.lazy
        return c

    def cp(nd):
        if nd is None:
            return None
        nid = id(nd)
        if nid in memo:
            return memo[nid]
        c = fresh(nd)
        memo[nid] = c
        dslots = dang.get(nid, ())
        c.out = None if 1 in dslots else cp(nd.out)
        if nd.kind == 's':
            c.out2 = None if 2 in dslots else cp(nd.out2)
        return c

    new_start = cp(frag.start)
    new_ends = [(memo[id(node)], slot) for node, slot in frag.ends]
    return _Frag(new_start, new_ends)


# --------------------------- Pike VM execution ---------------------------

_caps_size = 0


def _class_match(node, ch):
    ok = ch in node.chars
    if not ok:
        for e in node.cats:
            if e == 'd':
                ok = ch in DIGIT_CHARS
            elif e == 'D':
                ok = ch not in DIGIT_CHARS
            elif e == 'w':
                ok = ch in WORD_CHARS
            elif e == 'W':
                ok = ch not in WORD_CHARS
            elif e == 's':
                ok = ch in SPACE_CHARS
            else:
                ok = ch not in SPACE_CHARS
            if ok:
                break
    return (not ok) if node.neg else ok


def _char_ok(node, ch):
    if node.kind == 'c':
        return node.ch == ch
    if node.kind == '.':
        return ch != '\n'
    return _class_match(node, ch)


def _number_nodes(start):
    num = [0]
    stack = [start]
    seen = set()
    while stack:
        nd = stack.pop()
        if nd is None or id(nd) in seen:
            continue
        seen.add(id(nd))
        nd.num = num[0]
        num[0] += 1
        stack.append(nd.out)
        if nd.kind == 's':
            stack.append(nd.out2)
    return num[0]






def _execute(start, nstates, ngroups, text, anchored):
    """Pike VM run in a single left-to-right pass (linear time).

    Threads (state, captures) are kept in a strict preference order that
    mirrors Python re: threads started at an earlier position come first, and
    within one start position DFS order applies -- greedy splits explore the
    loop branch before the exit, lazy splits the reverse, alternations left to
    right. Only the first thread reaching each NFA state survives.

    For search a fresh start thread is injected at every position (but never
    past a leading ^, which is enforced inside the closure), so all start
    positions are explored in one O(nstates * n) pass; patterns such as
    (a+)+$ never blow up.

    The accepting thread with the best preference wins. A thread's global
    preference is (start position, per-step rank); we carry an integer
    priority: smaller = preferred.
    """
    n = len(text)
    ncaps = ngroups * 2

    # priority counter so older/higher-pref threads keep smaller numbers
    threads = []            # list of [node, caps, base]
    marks = [-1] * nstates  # state num -> index in threads (current step)
    prio = []               # priority parallel to threads
    counter = [0]
    posbox = [0]

    def add(nd, caps, base):
        stack = [(nd, caps)]
        while stack:
            node, cp = stack.pop()
            while node is not None:
                k = node.kind
                if k == 'e':
                    node = node.out
                    continue
                if k == 'a':
                    if node.anchor == '^':
                        if base != 0:
                            break
                    else:
                        p = posbox[0]
                        if not (p == n or (p == n - 1 and text[p] == '\n')):
                            break
                    node = node.out
                    continue
                if k == 'g':
                    cp = list(cp)
                    cp[node.gid * 2 + (1 if node.close else 0)] = posbox[0]
                    node = node.out
                    continue
                num = node.num
                if marks[num] != -1:
                    break
                if k == 's':
                    pref = node.out2 if node.lazy else node.out
                    alt = node.out if node.lazy else node.out2
                    stack.append((alt, cp))
                    node = pref
                    continue
                marks[num] = len(threads)
                threads.append([node, cp, base])
                prio.append(counter[0])
                counter[0] += 1
                break

    best = None  # (priority, caps)

    def seed(pos):
        if anchored and pos != 0:
            return
        init = [-1] * ncaps
        init[0] = pos
        posbox[0] = pos
        add(start, init, pos)

    # position 0 initial threads (before consuming any char)
    seed(0)
    pos = 0
    while True:
        # check acceptance: best-priority match thread present
        mi = -1
        for idx in range(len(threads)):
            if threads[idx][0].kind == 'm':
                mi = idx
                break
        if mi != -1:
            _, cp, _ = threads[mi]
            cc = list(cp)
            cc[1] = pos
            return cc
        if pos >= n:
            break
        ch = text[pos]
        old = threads
        oldprio = prio
        threads = []
        prio = []
        marks = [-1] * nstates
        posbox[0] = pos + 1
        for (node, cp, base), pr in zip(old, oldprio):
            if node.kind != 'm' and _char_ok(node, ch):
                # preserve priority ordering: temporarily reserve counter
                saved = counter[0]
                counter[0] = pr * (nstates + 1) + (saved % (nstates + 1))
                add(node.out, cp, base)
        # inject a fresh start thread at next position AFTER existing threads
        counter[0] = (counter[0] // (nstates + 1) + 1) * (nstates + 1)
        seed(pos + 1)
        pos += 1
    return None


# ------------------------------ Public API -------------------------------

class Match(object):
    def __init__(self, text, caps, ngroups):
        self._text = text
        self._caps = caps
        self._ng = ngroups

    def span(self, group=0):
        i = group * 2
        a, b = self._caps[i], self._caps[i + 1]
        if a < 0:
            return (-1, -1)
        return (a, b)

    def start(self, group=0):
        return self.span(group)[0]

    def end(self, group=0):
        return self.span(group)[1]

    def group(self, group=0):
        a, b = self.span(group)
        if a < 0:
            return None
        return self._text[a:b]

    def groups(self):
        out = []
        for g in range(1, self._ng):
            a, b = self.span(g)
            out.append(None if a < 0 else self._text[a:b])
        return tuple(out)

    def __repr__(self):
        return "<regex_engine.Match object; span=%r, match=%r>" % (
            self.span(), self.group())


class Pattern(object):
    def __init__(self, pattern):
        self.pattern = pattern
        parser = _Parser(pattern)
        self._start, self._ng = parser.parse()
        self._nstates = _number_nodes(self._start)

    def _do(self, text, anchored):
        caps = _execute(self._start, self._nstates, self._ng, text, anchored)
        if caps is None:
            return None
        return Match(text, caps, self._ng)

    def match(self, text):
        return self._do(text, True)

    def search(self, text):
        return self._do(text, False)


def compile(pattern):
    return Pattern(pattern)


def match(pattern, text):
    return Pattern(pattern).match(text)


def search(pattern, text):
    return Pattern(pattern).search(text)


# ------------------------------ Self tests -------------------------------

def _selftest():
    cases = [
        ("a", "a", (0, 1), True),
        ("a", "ba", None, True),
        ("a", "ba", (1, 2), False),
        ("ab", "xab", (1, 3), False),
        ("a*", "", (0, 0), True),
        ("a*", "aaab", (0, 3), True),
        ("a+", "aaab", (0, 3), True),
        ("a?", "b", (0, 0), True),
        ("a{2,3}", "aaaa", (0, 3), True),
        ("a{2}", "aaa", (0, 2), True),
        ("a{2,}", "aaaa", (0, 4), True),
        ("a*?", "aaa", (0, 0), True),
        ("a+?", "aaa", (0, 1), True),
        ("a??", "a", (0, 0), True),
        ("a{2,3}?", "aaa", (0, 2), True),
        ("(ab)+", "ababx", (0, 4), True),
        ("(a|b)*", "baba", (0, 4), True),
        ("(a+)(b+)", "aaabb", (0, 5), True),
        ("(a*)b", "aaab", (0, 4), True),
        ("^a", "a", (0, 1), True),
        ("^a", "ba", None, False),
        ("a$", "ba", (1, 2), False),
        ("a$", "ab", None, False),
        ("a$", "a\n", (0, 1), True),
        ("^", "", (0, 0), True),
        ("$", "", (0, 0), True),
        (".", "x", (0, 1), True),
        (".", "\n", None, True),
        (".*", "abc", (0, 3), True),
        (".*?", "abc", (0, 0), True),
        ("[abc]", "xbyc", (1, 2), False),
        ("[^abc]", "abcd", (3, 4), False),
        ("[a-z]+", "aBc", (0, 1), True),
        (r"\d+", "ab123", (2, 5), False),
        (r"\w+", "ab_1", (0, 4), True),
        (r"\s+", "a  b", (1, 3), False),
        (r"\D+", "12abc", (2, 5), False),
        ("a.b", "axb", (0, 3), True),
        (r"a\.b", "a.b", (0, 3), True),
        ("(foo|bar)", "bar", (0, 3), True),
        ("colou?r", "colour", (0, 6), True),
        ("", "abc", (0, 0), True),
        ("()", "abc", (0, 0), True),
        ("(a|)", "a", (0, 1), True),
        ("a{0}", "a", (0, 0), True),
        (r"[\d]+", "a12", (1, 3), False),
        (r"[^\d]", "1a", (1, 2), False),
        (r"\n", "a\nb", (1, 2), False),
        (r"a\nb", "a\nb", (0, 3), True),
    ]
    for pat, text, span, anchored in cases:
        m = match(pat, text) if anchored else search(pat, text)
        got = None if m is None else m.span()
        assert got == span, "pat=%r text=%r want=%r got=%r" % (
            pat, text, span, got)

    m = search(r"(\d+)-(\d+)", "123-456")
    assert m.groups() == ("123", "456"), m.groups()
    assert m.group(1) == "123"
    m = match("((a)(b))", "ab")
    assert m.groups() == ("ab", "a", "b"), m.groups()
    m = match("(a+)+$", "aaa")
    assert m.span() == (0, 3)

    big = "a" * 100000
    assert match("(a+)+$", big).span() == (0, 100000)
    assert search("(a+)+$", big + "b") is None
    assert search("(a*)*b", big + "c") is None
    assert search("(a|a?)+$", big + "b").span() == (100001, 100001)

    p = compile("b")
    assert p.match("b").span() == (0, 1)
    assert p.search("ab").span() == (1, 2)
    print("self-test OK")


if __name__ == "__main__":
    _selftest()

