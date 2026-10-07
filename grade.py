#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""task20（正则引擎）判分脚本。

规则：
1. 交付 regex_engine.py，暴露 compile(pattern)、match(pattern, text)、search(pattern, text)。
   compile 返回的对象带 .match(text)/.search(text) 方法；匹配结果对象带 .span()
   （返回 (start, end) 元组），未匹配返回 None。
2. 普通用例：一批确定性 pattern × text，与 Python re 的 match/search 对拍 .span()，
   匹配区间必须完全一致（含空匹配、贪婪/懒惰、交替顺序、锚点、转义等边界）。
3. 恶意用例：(a+)+$ 这类灾难性回溯模式，匹配 10^5 长度串，必须在 1 秒内返回。
4. 全程本地离线，只许用标准库。

用法：
  python3 grade.py
  python3 grade.py --module path/to/regex_engine.py
"""

import argparse
import importlib.util
import os
import re
import signal
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


class TimedOut(Exception):
    pass


def _alarm(signum, frame):
    raise TimedOut()


if hasattr(signal, "SIGALRM"):
    signal.signal(signal.SIGALRM, _alarm)


# ---------------- 普通用例（与 Python re 对拍 span） ----------------

PATTERNS = [
    'a', 'ab', 'a|b', 'ab|a', 'a|ab', 'a*', 'a+', 'a?', 'a{2}', 'a{2,}', 'a{2,4}',
    'a*?', 'a+?', 'a??', 'a{2,4}?',
    '(ab)+', '(a|b)*', '(a+)(b+)', '(a*)b', r'(\d+)-(\d+)',
    '^a', 'a$', '^a$', '^', '$', '.', '.*', '.+', '.*?',
    '[abc]', '[^abc]', '[a-z]', '[0-9]+', '[a-zA-Z_]+',
    r'\d+', r'\w+', r'\s+', r'\D+', r'\W+', r'\S+',
    'a.b', 'a\\\\b', r'a\.b', r'\d\d\d',
    '(foo|bar)', 'x{1,3}', 'colou?r', '(a|ab)+',
    '', '()', '(a)', '(a|)', 'a|', '|a',
    '((a)(b))', '(a)(b)(c)', 'a{0}', 'a{0,}',
    '[a-c]', r'[\d]', r'[\D]', r'[a\d]', r'[^\d]',
    '(ab|cd|ef)', '(x+)(y*)(z?)', 'a{2,2}',
    r'\n', r'\t', r'a\nb', r'[\n]', r'[^\n]',
]

TEXTS = [
    '', 'a', 'b', 'ab', 'ba', 'aa', 'aaa', 'aaaa', 'aaabbb', 'abc',
    '123', 'abc123', '  ', 'a1 b2', 'foo bar', 'foobar', 'colour', 'color',
    '123-456', 'x', 'xx', 'xxx', 'xxxx', 'a.b', 'aXb', 'axb',
    'hello world', 'hello', 'world', 'the quick brown fox',
    'c', 'cd', 'abcd', 'efef', 'zzz', 'a\\b', 'ab\ncd', '\n', 'a\nb',
]


def _span(m):
    return None if m is None else m.span()


def run_ordinary(mod):
    fails = 0
    total = 0
    first_err = None
    for p in PATTERNS:
        for t in TEXTS:
            try:
                rm = re.match(p, t)
                rs = re.search(p, t)
            except re.error:
                continue
            total += 1
            try:
                om = mod.match(p, t)
            except Exception as e:
                fails += 1
                if first_err is None:
                    first_err = ('match 抛异常', p, t, repr(e))
                continue
            if _span(rm) != _span(om):
                fails += 1
                if first_err is None:
                    first_err = ('match 区间不一致', p, t, _span(rm), _span(om))
            total += 1
            try:
                os_ = mod.search(p, t)
            except Exception as e:
                fails += 1
                if first_err is None:
                    first_err = ('search 抛异常', p, t, repr(e))
                continue
            if _span(rs) != _span(os_):
                fails += 1
                if first_err is None:
                    first_err = ('search 区间不一致', p, t, _span(rs), _span(os_))
    return total, fails, first_err


# ---------------- 恶意用例（灾难性回溯，必须 1 秒内返回） ----------------
# 期望结果手工推导（不能直接调 Python re，它在这些模式上会灾难性回溯）：
#   - 全 a 的串：模式匹配整段，返回 (0, n)。
#   - 末尾带 b/c/y 的串：要么失配返回 None，要么（(a|a?)+$）在结尾空匹配 (n, n)。

N = 100000

MALICIOUS = [
    ('(a+)+$', 'a' * N, (0, N)),
    ('(a+)+$', 'a' * N + 'b', None),
    ('(a+)+b', 'a' * N + 'c', None),
    ('(a|aa)+$', 'a' * N, (0, N)),
    ('(a*)*b', 'a' * N + 'c', None),
    ('(a|a?)+$', 'a' * N + 'b', (N + 1, N + 1)),
    ('([a-z]+)*x', 'a' * N + 'y', None),
]

MALICIOUS_MATCH = [
    ('(a+)+$', 'a' * N, (0, N)),
    ('(a+)+$', 'a' * N + 'b', None),
    ('(a+)+b', 'a' * N + 'c', None),
]


def _run_one(mod, kind, pat, text, exp):
    """跑单个恶意用例，返回 (ok, err)。"""
    t0 = time.perf_counter()
    try:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(1)
        fn = mod.match if kind == 'match' else mod.search
        m = fn(pat, text)
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
        dt = time.perf_counter() - t0
    except TimedOut:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
        return False, ('%s 超时' % kind, pat)
    except Exception as e:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
        return False, ('%s 抛异常' % kind, pat, repr(e))
    if dt > 1.0:
        return False, ('%s 超时(%.3fs)' % (kind, dt), pat)
    got = _span(m)
    if got != exp:
        return False, ('%s 区间不一致' % kind, pat, exp, got)
    return True, None


def run_malicious(mod):
    fails = 0
    total = 0
    first_err = None
    for pat, text, exp in MALICIOUS:
        total += 1
        ok, err = _run_one(mod, 'search', pat, text, exp)
        if not ok:
            fails += 1
            if first_err is None:
                first_err = err
    for pat, text, exp in MALICIOUS_MATCH:
        total += 1
        ok, err = _run_one(mod, 'match', pat, text, exp)
        if not ok:
            fails += 1
            if first_err is None:
                first_err = err
    return total, fails, first_err


def load_module(path):
    name = "regex_engine"
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for fn in ("compile", "match", "search"):
        if not hasattr(mod, fn):
            raise AttributeError("缺少 %s" % fn)
    return mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=os.path.join(HERE, "regex_engine.py"))
    args = ap.parse_args()

    print("=" * 60)
    print("判分开始")

    if not os.path.exists(args.module):
        print("[FAIL] 找不到 %s" % args.module)
        sys.exit(1)

    try:
        mod = load_module(args.module)
    except Exception as e:
        print("[FAIL] 导入模块失败：%r" % (e,))
        sys.exit(1)

    all_ok = True

    total, fails, first = run_ordinary(mod)
    print("[普通用例] 共 %d 项对拍，失败 %d" % (total, fails))
    if first:
        print("  首个失败：%r" % (first,))
    if fails > 0:
        all_ok = False

    total, fails, first = run_malicious(mod)
    print("[恶意用例] 共 %d 项，失败 %d" % (total, fails))
    if first:
        print("  首个失败：%r" % (first,))
    if fails > 0:
        all_ok = False

    # 自测入口：模块能作为脚本运行并退出 0
    import subprocess
    r = subprocess.run([sys.executable, args.module], cwd=HERE,
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        print("[自测入口] 作为脚本运行退出码 %d，判定不过" % r.returncode)
        all_ok = False
    else:
        print("[自测入口] 作为脚本运行正常")

    print("=" * 60)
    print("总结论：", "PASS" if all_ok else "FAIL")
    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
