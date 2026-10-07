# 正则引擎

## 你要交付什么

一个模块 `regex_engine.py`，暴露三个入口：

```python
import regex_engine as R

R.compile(pattern)          # 返回编译对象
R.match(pattern, text)      # 锚定匹配
R.search(pattern, text)     # 搜索匹配
```

- `compile(pattern)` 返回一个对象，带 `.match(text)` 和 `.search(text)` 方法。
- 模块级 `match`/`search` 直接返回匹配结果：命中返回匹配对象，未命中返回 `None`。
- 匹配对象带 `.span()`（返回 `(start, end)` 元组）、`.group(n)`、`.groups()`。

模块还要能直接当脚本跑一段自测：

```bash
python3 regex_engine.py
```

自测跑完退出码为 0。

## 支持的语法

字面量、`.` 通配、`[...]` 和 `[^...]` 字符类、`\d \D \w \W \s \S` 和 `\n \t \r` 转义、
`* + ? {m} {m,} {m,n}` 区间量词及各自的懒惰版（`*? +? ?? {m,n}?`）、`(...)` 分组、
`|` 交替、`^ $` 锚点。

匹配语义对齐 Python 的 `re`：左优先（最早起点优先）、贪婪和懒惰按量词走、交替按书写先后、
`^` 只匹配串首、`$` 匹配串尾或结尾换行符之前。

## 判分标准（`grade.py`）

```bash
python3 grade.py
```

- 普通用例：约 500 个确定性 pattern × text，与 Python `re` 的 `match`/`search` 对拍 `.span()`，
  匹配区间必须完全一致，覆盖空串、贪婪/懒惰、交替顺序、锚点、转义这些边界。
- 恶意用例：`(a+)+$` 这类灾难性回溯模式匹配 10^5 长度的串，每个必须在 1 秒内返回。
- 自测入口：模块能作为脚本运行并退出码 0。

全部通过输出 `PASS`。

## 约束

- 全程本地离线，只用标准库，不调现成正则库（`re`、`regex` 都不行）。
- 不允许灾难性回溯。写朴素回溯引擎一测 `(a+)+$` 就指数爆炸，要过恶意用例得真懂
  Thompson NFA、Pike 虚拟机或者带缓存的搜索方案，把复杂度压到线性或接近线性。
