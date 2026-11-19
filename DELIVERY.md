# 取证导出器重放字节失真修复 — 交付文档

## 1. 根因定位

取证导出器 `mitmproxy/addons/export.py` 的 `request_content_for_console()`
把请求体交给 shell 重放时存在四个独立缺陷，curl 与 httpie 两条路径共用同一
构造函数，因此同源失真：

| 编号 | 故障类 | 旧构造 | 根因 |
|----|--------|--------|------|
| 类1 | 百分号编码 / 模板占位体变成十六进制垃圾 | `curl -d "$(printf '<体>')"` | 录制体被当作 `printf` 的**格式串**，体里的 `%2f`、`%x`、`%d` 被 printf 当作转换说明符消费（如 `%x` 对缺失参数输出 `0`），`{{...}}` 虽不特殊但与受污染片段同体 |
| 类2 | 含反斜杠的 Windows 路径体中间出现制表符 | 同上 | printf 解释体内容里的反斜杠转义：`\t`→制表符、`\n`→换行，`C:\tmp\new` 被打成 `C:<TAB>mp<LF>ew` |
| 类3 | 以换行结尾的体尾部换行丢失 | `"$(printf ...)"` | shell 命令替换 `$(...)` 会剥离输出的**全部尾随换行** |
| 类4 | `@` 开头的体被当文件引用、请求未发出 | `curl -d '@...'` | curl 的 `-d/--data` 把首字符 `@` 后的内容当文件名读取，文件不存在即报错，请求根本不发出 |

httpie 路径另有两处同源问题：
- 旧构造 `http ... <<< '<体>'` 使用 here-string，而 `<<<` 是 **bash 专有**，
  在精简 POSIX shell（dash）下直接 `Syntax error: redirection unexpected`，
  命令无法执行；
- 即便在 bash 下，here-string 会**追加一个换行**，任何体都多一个尾字节。

不含控制字符的对照体旧实现走 `shlex.quote` 直传分支，不经 printf/`$()`，
因此字节一致 —— 与题面"对照组正常"的观测吻合。

## 2. 修复方案与构造取舍（自行设计部分）

### 2.1 判据（curl 与 httpie 同判据）

对导出的请求体文本，满足任一条件即走"管道 printf"构造，否则 curl 保留
简单直传：
1. 体含任意 ASCII 控制字符（码点 < 32）；
2. 体以 `@` 开头（仅 curl 需要，但两路径统一由 `_needs_pipe_encoding` 判定）。

### 2.2 选定的命令构造

**控制字符 / @开头体（curl 与 httpie 通用）：**

```
printf '<格式串>' '<段1>' '<段2>' ... | curl  ... --data-binary @-
printf '<格式串>' '<段1>' '<段2>' ... | http  ...
```

构造规则（`request_body_pipe()`）：
- 把体切分为**字面文本段**与**控制字符**交替的序列；
- 每个字面段对应格式串里一个 `%s` 转换、参数为该段原文（经 `shlex.quote`）。
  因为走 `%s` 而非格式串本体，体里的 `%` 与反斜杠都**永不被解释**，类1、类2
  从机制上消除；
- 每个控制字符对应一个 `%b` 转换、参数为三位八进制 `\0NN`（POSIX printf
  保证解码为该字节），NUL、TAB、CR、LF 均可表达；
- 末尾追加一个零宽哨兵 `%s` + 空参数。实测 Git for Windows 自带的 dash/bash
  printf 在格式串以转换符结尾时，不按 POSIX 轮次复用格式串，而会把剩余参数
  灌进末尾转换导致段错位；追加一个不产生字节的 `%s ''` 使格式串"干净收尾"，
  在 dash 与 bash 下逐字节一致；
- printf 输出经**管道**送入工具，不经过 `$()`，尾随换行不被剥离（类3）；
  curl 端用 `--data-binary @-` 而非 `-d`，既不剥 CR/LF 也不把 `@` 当文件
  （类4），管道字节原样转发。

**无控制字符且非 @ 开头的体：**
- curl：保留旧的 `-d <shlex.quote(体)>` 简单形态，对照组行为零回归；
- httpie：**统一改为管道** `printf %s%s '<体>' '' | http ...`。理由：here-string
  在 POSIX shell 是语法错误且必加换行，不存在能逐字节重放的 here-string 形态，
  管道是唯一同时满足"可直接粘贴执行 + 逐字节 + 跨 shell"的构造。

### 2.3 被否决的备选

- `printf '%b' '<整体转义体>'`：`%b` 会解码参数里的反斜杠，要保字面反斜杠就得
  双写 `\`，但实测 dash/bash 对 `\\` 的 `%b` 处理与预期相反（`\\t` 仍出 TAB），
  无法同时满足类1与类2，否决。
- 维持 `<<<` 仅在 bash 使用：违反"精简 shell 原样粘贴"与逐字节要求，否决。
- 用临时文件 + `--data-binary @file`：引入文件系统副作用与清理负担，粘贴到
  复核工单时不是自包含单条命令，否决。
- base64 编码 + `base64 -d`：依赖 base64 工具且命令可读性差，取证场景要求最小
  依赖，而 POSIX printf 是任何合规 shell 内建，故不采用。

### 2.4 二进制体

非合法 Unicode 的体仍由 `_request_text()` 抛 `CommandError`（沿用旧约束，
`shlex.quote` 不支持 bytes），行为与旧实现一致，不在本次四类体范围内。

## 3. 题面要求 → 改动落点（逐条）

| 题面要求 | 落点 |
|---------|------|
| 类1 百分号/模板体逐字节一致 | `request_body_pipe()` 字面段走 `%s`，`%` 永不被当格式说明符；测试 `test_special_bodies_use_byte_exact_pipe[class1]`（curl/httpie 各一） |
| 类2 反斜杠路径体逐字节一致 | 反斜杠留在 `%s` 字面段，不做任何转义解释；测试 class2 两路径 |
| 类3 尾部换行不丢 | 管道传输替代 `$()`，换行作为 `%b \012` 实参；测试 class3 两路径 |
| 类4 @开头不再被当文件 | curl 改 `--data-binary @-` 管道，体不再以 `-d` 实参出现；测试 class4 及 `test_at_prefixed_body_without_control_uses_pipe` |
| 多行体内部换行不回归 | `%b \0NN` 逐控制字符保序；`test_multiline_body_internal_newlines_preserved`（curl/httpie 各一，含 CR/LF） |
| 无控制字符对照体不回归 | curl 保留 `-d shlex.quote(体)`：`test_control_free_body_keeps_plain_dash_d_form`；httpie 管道化但逐字节：`test_control_free_body_uses_pipe_without_here_string` |
| 命令可直接复制执行 | 输出仍为单行 shell 命令，仅 POSIX 内建 printf + 管道，dash/bash 实测均可粘贴执行 |
| httpie 与 curl 同判据 | 两路径共用 `_request_text`/`_needs_pipe_encoding`/`request_body_pipe`；同一份参数化用例矩阵两路径各跑一遍 |
| 四类体构造断言 + 多行对照并入既有测试矩阵、同一框架 | 全部加入 `test/mitmproxy/addons/test_export.py` 既有 `TestExportCurlCommand`/`TestExportHttpieCommand`，沿用 pytest + tflow/tutils |
| 既有测试保持通过、改动面收在导出器及其测试 | 代码仅改 `mitmproxy/addons/export.py` 与 `test/mitmproxy/addons/test_export.py`；仅更新断言旧构造串的 4 个既有用例（见下） |
| 验收以指定 pytest 命令零失败为准 | 见第 5 节实测读数 |

被更新断言的既有用例（断言的是旧的错误构造，属本次修复必须同步的期望）：
- `TestExportCurlCommand.test_expand_escaped`
- `TestExportHttpieCommand.test_post`
- `TestExportHttpieCommand.test_patch`
- `TestExportHttpieCommand.test_escape_single_quotes_in_body`

## 4. 改动文件登记

| 文件 | 性质 | 改动内容 |
|------|------|---------|
| `mitmproxy/addons/export.py` | 修复 | 新增 `_request_text`、`_needs_pipe_encoding`、`request_body_pipe`；重写 `request_content_for_console` 为简单体专用；`curl_command` 控制字符/@体改 `printf 管道 + --data-binary @-`；`httpie_command` 全 body 改 printf 管道、移除 here-string |
| `test/mitmproxy/addons/test_export.py` | 测试 | 更新 4 个旧断言；新增四类体参数化构造断言（curl 4 + httpie 4）、多行体对照（2）、对照组（curl 1 + httpie 1）、@前缀无控制字符（curl 1），共 13 个新测试节点 |
| `acceptance/echo_server.py` | 验收脚手架（新增，非产品代码） | 零依赖标准库回显服务，监听 127.0.0.1，回显完整请求字节 |
| `acceptance/replay_lib.py` | 验收脚手架（新增） | 回显响应解析，按首个头体分界精确取重放体 |
| `acceptance/acceptance_run.py` | 验收脚手架（新增） | 五类构造输入 × curl/httpie × bash/dash 逐字节比对，输出差异位置 |
| `acceptance/acceptance_before.txt` | 验收记录（新增） | 修复前旧实现真实执行读数 |
| `acceptance/acceptance_after.txt` | 验收记录（新增） | 修复后真实执行读数（20/20 一致） |

产品改动面严格收在导出器实现与其测试两个文件；`acceptance/` 为独立验收脚手架，
不被 mitmproxy 包导入，不影响产品与既有测试。

## 5. 验收实测读数

### 5.1 单元/格式测试（题面指定验收命令）

命令：
```
python -m pytest test/mitmproxy/addons/test_export.py -q --timeout=60
```
实测最终读数：**54 passed, 5 warnings**（零失败）。
其中原 41 个既有用例（含 4 个同步更新断言者）全过，新增 13 个测试节点全过。
仓库内其他 addon 测试的失败均为 `async def functions are not natively
supported`，源于本机缺 dev 组 `pytest-asyncio`（该组依赖需 MSVC 构建工具），
与本次改动无关；非 async 类失败为 0。

### 5.2 逐类逐字节真实重放（读数口径按题面）

口径：五类自构造输入（四类故障体 + 无控制字符对照体各一例），导出命令对
快照内本地回环 `http://127.0.0.1:8765` 回显服务**真实执行**，捕获重放字节与
录制原文逐字节比对；每例在 bash 5.3 与 dash（POSIX）两个 shell、curl 与
httpie 两个导出器下各执行一次，共 20 次。复现步骤：
```
.venv/Scripts/python -I acceptance/echo_server.py 8765     # 终端1
.venv/Scripts/python -I acceptance/acceptance_run.py       # 终端2
```
实测最终读数（完整输出存 `acceptance/acceptance_after.txt`）：

| 构造输入（录制字节） | curl/bash | curl/dash | httpie/bash | httpie/dash |
|----------------------|-----------|-----------|-------------|-------------|
| 类1 `search=%2fhome&tpl={{user}}/profile&pct=%x&id=99%d\n` (51B) | 一致 | 一致 | 一致 | 一致 |
| 类2 `path=C:\tmp\new\report.txt\n` (27B) | 一致 | 一致 | 一致 | 一致 |
| 类3 `line1\nline2\n` (12B) | 一致 | 一致 | 一致 | 一致 |
| 类4 `@replay-token: keep me` (22B) | 一致 | 一致 | 一致 | 一致 |
| 对照 `simple-body-123` (15B) | 一致 | 一致 | 一致 | 一致 |

汇总：**20/20 byte-exact，0 failing，进程退出码 0**。

修复前同口径读数（`acceptance/acceptance_before.txt`）摘要：curl 四类体在
bash/dash 全部不一致或请求未发出、两类对照一致；httpie 在 bash 下类1/2/4/
对照均不一致、类3 因 here-string 补换行巧合"一致"，在 dash 下全部因
`<<<` 语法错误无法执行。前后对照证明四类失真均已消除且对照组无回归。

### 5.3 附加边界实测（同口径，均逐字节一致）

单引号/双引号混合体、含 NUL 体、纯换行体、TAB+百分号体、纯反斜杠体、
带 `charset=utf-8` 的 unicode 体，在 curl/httpie × bash/dash 下 24/24 一致。
说明：请求体未声明 charset 时 mitmproxy 按 latin-1 解码文本是旧有约束（旧
导出器同样存在），与本次命令构造无关，故 unicode 用例显式带 utf-8 声明。

## 6. 环境与可复现性

- 全程在快照工作区内完成；回显服务与验收脚本仅用 Python 标准库，零外部包依赖。
- httpie 不在仓库 `uv.lock` 中，验收用 venv 内安装的 httpie 3.2.4（仅验收
  脚手架使用，产品代码不依赖）；curl 用 git-bash 自带 8.19 与 Windows 系统
  8.21 均实测通过。
- 子进程显式 `LC_ALL=C.UTF-8` 并继承系统环境，避免 Windows ANSI 代码页对
  非 ASCII 命令的双重编码。
