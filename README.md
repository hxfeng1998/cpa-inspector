# CPA Inspector

[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（下称 CPA）的原生插件：把经过代理的每一次模型调用完整抓下来，重组成可读的对话，并持续回答两个问题——

- **这条渠道可信吗？** 第三方中转有没有偷换模型、往响应里注入工具调用、截断响应、虚报 token；我自己有没有把密钥随上下文发出去。
- **上游是不是悄悄变了？** 为每种协议、每种流事件、每个模型建立字段基线，之后任何新增字段、新枚举值、类型变化、必现字段消失、新响应头都会被报告——模型进入灰测、渠道切换后端，通常最先体现在这里。

插件**只观察、不改写**：所有钩子都返回"不修改"，内部错误与 panic 会被吞掉，不影响代理转发。

![概览](docs/screenshots/overview.png)

## 目录

- [功能一览](#功能一览)
- [安装](#安装)
- [配置项](#配置项)
- [检查项](#检查项)
- [字段漂移是怎么判定的](#字段漂移是怎么判定的)
- [能看到什么，看不到什么](#能看到什么看不到什么)
- [安全与隐私](#安全与隐私)
- [性能开销](#性能开销)
- [常见问题](#常见问题)
- [开发](#开发)
- [许可证](#许可证)

## 功能一览

**请求列表**：每行一次模型调用，显示 请求模型 → 上游模型、协议路由（如 `claude → openai`）、渠道、结束原因、token、首包 / 总耗时，以及这次请求触发的发现项。支持按模型、渠道、级别、结果筛选和全文搜索。

![请求列表](docs/screenshots/requests.png)

**请求详情**：按报文的四段分页签，每段统一为 **起始行 → Headers → Body**，和浏览器 DevTools 的读法一致。

| 页签 | 内容 |
|---|---|
| 摘要 | 耗时、token、凭据，以及这次请求的全部发现项 |
| 对话 | 把请求体还原成 system / user / assistant / 工具调用 / 工具结果，末尾接上本次响应。兼容 Claude、OpenAI Chat、OpenAI Responses（含新版 Codex）、Gemini 四种协议 |
| ① 客户端请求 | 客户端发给 CPA 的请求头与请求体 |
| ② 发往上游 | CPA 经协议翻译后实际发给渠道的请求体 |
| ③ 上游响应 | 渠道返回的**翻译前原文**：响应头、usage、逐事件的 SSE 流 |
| ④ 返回客户端 | CPA 翻译后返回给客户端的响应 |

Body 可以在 结构化（可折叠 JSON 树，基线之外的字段高亮）/ 重组内容 / 事件流（带毫秒时间偏移）/ 原文（一键复制）之间切换。

![请求详情：发现项](docs/screenshots/detail-findings.png)

![请求详情：响应重组与事件流](docs/screenshots/detail-response.png)

**字段图谱**：每个作用域（方向 × 协议 × 事件类型）下观测到的全部字段，按模型并排显示出现率——哪个模型多了字段、少了字段一眼可见。下图是某渠道从某一刻起开始返回 `usage.inference_geo`、`usage.iterations` 的样子：

![字段图谱](docs/screenshots/schema.png)

**发现**：同一问题跨请求聚合成一条并计数，按 渠道安全 / 隐私外泄 / 协议完整性 / 字段漂移 分类。确认后不再计入待办；确认漂移类发现等于把该字段并入基线。

**主题**：完全跟随 CPA 管理面板（white / dark / 默认暖色），切换实时生效；嵌入面板时自动改为顶部标签布局。

![暗色](docs/screenshots/overview-dark.png)

## 安装

### 前提

- CPA 版本需带动态库插件系统（本插件在 v7.3.9 上开发与验证），且为 **CGO 构建**。官方 Docker 镜像满足；自行编译需 `CGO_ENABLED=1`。
- 已设置 `remote-management.secret-key`（留空会关闭整个 Management API，界面取不到数据）。

### 1. 获取插件

**直接下载**（推荐）：到 [Releases](https://github.com/hxfeng1998/cpa-inspector/releases) 下载对应架构的压缩包并解压，得到 `cpa-inspector.so`。

| 文件 | 适用 | |
|---|---|---|
| `cpa-inspector-linux-`**`amd64`**`.tar.gz` | x86-64（Intel / AMD）处理器 | **绝大多数 VPS 和 PC 选这个** |
| `cpa-inspector-linux-`**`arm64`**`.tar.gz` | ARM 处理器：甲骨文 Ampere 免费机、AWS Graviton、树莓派（64 位系统） | 只有明确知道是 ARM 机器才选 |

两个名字只差一个字母，下载前在服务器上执行 `uname -m` 确认：

| `uname -m` 输出 | 下载 |
|---|---|
| `x86_64` | **amd64** |
| `aarch64` | **arm64** |

下错了不会损坏任何东西，只是 CPA 加载不了，启动日志里不会出现 `plugin loaded`。

`vX.Y.Z` 是固定版本；`latest` 是 main 分支最新一次自动构建。产物在与 CPA 官方镜像相同的 debian bookworm（glibc 2.36）上编译，可用 `SHA256SUMS` 校验。

**或者自行构建**，需要 Go 1.26+ 与 gcc：

```bash
git clone https://github.com/hxfeng1998/cpa-inspector.git && cd cpa-inspector
make build            # → dist/cpa-inspector.so（本机架构）
```

CPA 跑在 Docker 里时，建议用与官方镜像相同的基础镜像构建，保证 glibc 兼容；也可借此交叉出 ARM 版本：

```bash
make docker-build                          # linux/amd64
make docker-build PLATFORM=linux/arm64
```

> 产物文件名就是插件 ID，**不要改名**。

### 2. 放置

把 `cpa-inspector.so` 放进 CPA 工作目录下的 `plugins/`（直接放即可，不需要 `linux/amd64/` 子目录）。

**Docker 部署**需要把插件目录和数据目录挂进容器，否则容器里看不到插件，重建后数据也会丢：

```yaml
services:
  cliproxyapi:
    volumes:
      - ./config.yaml:/CLIProxyAPI/config.yaml
      - ./plugins:/CLIProxyAPI/plugins              # 插件本体
      - ./plugins-data:/CLIProxyAPI/plugins-data    # 请求记录、字段基线、发现项
```

### 3. 启用

CPA 默认 `plugins.enabled: false`，单个插件默认也是关闭的。在 `config.yaml` 里加上：

```yaml
plugins:
  enabled: true
  dir: "plugins"
  configs:
    cpa-inspector:
      enabled: true
      priority: 1
```

其余配置项都有默认值，见[配置项](#配置项)。

### 4. 重启并确认

重启 CPA。启动日志里应出现：

```
[cpa-inspector] ready: data_dir=plugins-data/cpa-inspector capture_upstream=true records=0
pluginhost: plugin registered plugin_id=cpa-inspector ... version=0.1.0
```

> 更新插件同样需要**重启 CPA**：仅覆盖 `.so` 文件宿主不会重新加载。

### 5. 打开界面

在 CPA 管理面板的侧边栏里会多出 **CPA Inspector** 菜单；也可以直接访问：

```
http(s)://<host>:<port>/v0/resource/plugins/cpa-inspector/ui
```

输入管理密钥即可。从服务器外部访问需要 `remote-management.allow-remote: true`，建议只经 HTTPS 反代暴露。

## 配置项

写在 `plugins.configs.cpa-inspector` 下，修改后 CPA 会热加载。

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `capture_upstream` | `true` | 抓取翻译前的上游原文与实际发往上游的请求体。关闭后插件不再声明该能力，宿主不会再调用，见[性能开销](#性能开销) |
| `data_dir` | `plugins-data/cpa-inspector` | 数据目录，相对 CPA 工作目录。不可写时退化为纯内存模式 |
| `max_records` | `2000` | 最多保留的请求记录数，超出删最旧的 |
| `max_disk_mb` | `1024` | 请求记录占用磁盘上限 |
| `max_body_mb` | `8` | 单个请求 / 响应体的保存上限，超出部分只分析、不保存 |
| `learn_samples` | `30` | 基线学习样本数：每个作用域的前 N 个请求只学习、不报告 |
| `scan_secrets` | `true` | 扫描请求体里的密钥、私钥、带口令的连接串 |

## 检查项

| 类别 | 规则 | 级别 |
|---|---|---|
| 渠道安全 | 上游自报模型与请求模型不一致（跨厂商，如请求 Claude 却自报 GLM，则为严重） | 警告 / 严重 |
| | **渠道改写了请求**：上游回显的 `instructions` / `tools` / `parallel_tool_calls` / `reasoning.effort` 等与发出的请求不一致（见下） | 警告 / 留意 |
| | 响应调用了请求里没声明的工具 | 严重 |
| | 响应含工具调用，但请求里找不到任何工具声明（无法校验，多半是插件尚不认识的声明方式） | 留意 |
| | 工具入参含高危模式：`curl … \| sh`、base64 解码执行、反弹 shell、写 `authorized_keys`、读凭据并外发、`rm -rf /` … | 警告 |
| | Claude 消息 ID 不是历史上的 `msg_01…` / `msg_bdrk_…` / `msg_vrtx_…` 形态。弱证据：中转常重写 ID，官方格式也可能调整；仅当同时缺 thinking 签名才升为警告 | 备查 / 警告 |
| | Claude thinking 块缺少 `signature` | 警告 |
| | 上游计费的输入 token 远超请求体字节数所能容纳的量（隐藏提示词注入 / 虚报） | 警告 |
| | 上游为公网明文 HTTP | 警告 |
| | 响应里出现请求上下文之外的域名（聚合后可看出被插入的推广链接） | 备查 |
| 隐私外泄 | 请求体含私钥、AWS / GitHub / Anthropic / OpenAI / Google / Slack / Stripe 密钥、JWT、带口令的连接串。证据始终打码；渠道为官方端点时降为备查 | 警告 |
| 缓存与计费 | **同一会话的提示词缓存失效**：本轮与上一轮共享 ≥90% 前缀、间隔 ≤5 分钟、上一轮输入 ≥2048 token，缓存读却不到预期的一半。给出损失的 token 数与归因（渠道变了 / 凭据变了 / 渠道注入的 instructions 变了 / 都没变＝渠道内部切换了上游账号） | 留意 / 警告 |
| 协议完整性 | 流缺 `message_start` / `message_stop` / `[DONE]` / `response.completed`，内容块未关闭，缺结束原因，成功但无内容 | 警告 / 留意 |
| | 上游下发了需要客户端回传的响应头（`X-Codex-Turn-State`），但 CPA 的 `passthrough-headers` 为关闭，客户端收不到也就无法回传 | 留意 |
| 字段漂移 | 见下节 | 留意 / 备查 |

**渠道改写请求的检测**：OpenAI Responses 协议的上游会在响应里回显实际生效的请求参数。插件把它与"CPA 实际发往上游的请求体"逐项比对——

- 回显里出现了请求中没有的 `instructions`：渠道注入了系统提示词（警告）。它会与客户端自带的提示词叠加甚至冲突，并计入每次请求的输入 token；若内容只是请求里已有提示词的副本，则为重复计费（留意）。
- `tools` 被添加（警告）或移除（留意）；`reasoning.effort` 被改写（警告）；`parallel_tool_calls`、`text.verbosity`、`service_tier`、`max_output_tokens` 被改写（留意）。
- 比对基准是 CPA 发出的请求而不是客户端请求，所以 CPA 自己做的改写（例如默认注入 `image_generation` 工具）不会被算到渠道头上；拿不到上游请求体时退回客户端请求，级别封顶为"留意"并注明。
- 渠道注入的提示词指纹同时并入"后端指纹"：同一渠道换了一份注入文本，会以漂移报告。

详情页"③ 上游响应"里有对应的"上游回显的生效参数"区块。Claude / Chat Completions 协议不回显请求参数，此项检查不适用。

工具声明的识别覆盖：顶层 `tools`（Claude / Chat / Responses / Gemini `functionDeclarations`），以及新版 Codex 放在 `input[]` 里的 `additional_tools` 条目（含 `namespace` 嵌套）。

## 缓存失效是怎么判定的

提示词缓存的命中条件是"同一账号（组织）下、前缀逐字节相同、未过期"。第三方渠道背后往往是账号池：会话中途被切到另一个账号，或渠道换了一份注入的 `instructions`，缓存就全部作废——OpenAI 系按原价重新计费，Claude 系还要再付一次缓存写入的溢价。

插件按会话追踪（会话标识优先取客户端的会话头，其次 `prompt_cache_key`、Claude Code 的 `metadata.user_id`）。判定刻意保守，只在"本该命中"时才报：

- 把请求拆成前缀条目（工具声明、system / instructions、每条消息）逐条哈希，与同会话里**已结束**的历史轮次比较，取公共前缀最长的一轮（Codex 会穿插"生成标题"之类的旁路请求，不能简单取上一条）；
- 公共前缀 ≥ 90%、间隔 ≤ 5 分钟、上一轮输入 ≥ 2048 token；新对话、上下文压缩后前缀变了的不算；并行发出的请求不互相比较；
- 此时缓存读 < 预期的一半，才报"缓存失效"。

概览页的模型 / 渠道表有"缓存损失"一列，可以直接比较各渠道。多条凭据被 CPA 轮询导致的失效会被归因为"凭据变了"，对应的解法是开启 `routing.session-affinity`。

## 字段漂移是怎么判定的

1. **形态提取**：把每份 JSON 展开成"路径 → 类型"。数组折叠为 `[]`；带 `type` / `role` 的多态对象按判别值分路径（`content[]<tool_use>.name`、`delta<text_delta>.text`），不同变体的字段互不干扰；判别类字段的取值记为伪路径（`stop_reason=end_turn`），用于发现新枚举值；工具入参、JSON Schema 这类用户数据子树不下钻。以 ID 为键的映射（如 `usage.attribution.items.rs_0e24…`，键每次请求都不同）折叠成通配并保留有语义的前缀（`items.{rs_*}`、`{at_*}`、纯数字 `{#}`），否则每个请求都会冒出一批"新字段"。
2. **作用域**：`方向 | 协议 | 事件类型`，例如 `upstream_response | claude | message_start`。经协议翻译得到的下游响应与直通的原生响应分开建基线（`claude←openai`）。
3. **学习期**：每个作用域的前 `learn_samples` 个**请求**（不是事件——一个流有上百个事件）全部并入基线。
4. **之后报告**：

| 信号 | 含义 |
|---|---|
| 新字段 / 新枚举值 | 基线里没有的路径或取值。同一次观测里祖先也是新的，只报祖先（新内容块类型只报一条） |
| 某模型开始返回此前没有的字段 | 该字段在其它模型里近乎必现（≥90%），这个模型观测充分却从未带过，现在带上了——典型的"悄悄进入灰测" |
| 必现字段缺失 | 该模型此前 ≥95% 出现的非数组字段这次没了——典型的"渠道换了后端"。仅对响应侧判定；取决于对话内容的路径（数组元素 `content[]…`、以 ID 为键的映射条目 `items.{ctco_*}…`）不参与——它们出现与否由对话里有没有对应的块 / 工具调用决定 |
| 类型变化 | 已有路径出现新的 JSON 类型 |
| 新响应头 / 新模型 | 上游响应头按渠道建基线；首次见到的模型名 |
| 后端指纹变化 | 按渠道学习消息 ID 的形态（如 `msg_01…(24)`）与 thinking 签名的有无；学习期后发生变化即报告——渠道换后端、开始重写 ID 的典型信号 |

请求侧（客户端自己发的内容）的变化只记为"备查"。审阅完当前状态后，可在设置页"以当前状态重建基线"。

## 能看到什么，看不到什么

数据来自 CPA 的插件钩子：

| 钩子 | 提供 |
|---|---|
| `request.intercept_before` / `after` | 客户端请求头与请求体、选定凭据后的上游协议与模型、重试次数 |
| `response.normalize_before` | 翻译前的上游响应（逐分片）+ 实际发往上游的请求体 |
| `websocket.response_event` | Codex WebSocket 执行器的上游事件 |
| `response.intercept_stream_chunk` / `intercept_after` | 返回客户端的响应 |
| `usage.handle` | 渠道 base-url、凭据、token 计数、TTFT、失败响应体、**完整的上游响应头** |
| `request.complete` | 终态：成功 / 失败 / 取消、状态码、错误 |

由此得到的四段报文：

| 段 | Headers | Body |
|---|---|---|
| ① 客户端请求 | 完整（凭据类脱敏） | 完整 |
| ② 发往上游 | **拿不到** | 经协议翻译的路由完整；同协议直通时等同 ① |
| ③ 上游响应 | 完整 | 经协议翻译的路由、以及 WebSocket 路由完整；其余同协议直通时等同 ④ |
| ④ 返回客户端 | 见下方说明 | 完整 |

**关于 ④ 的 Headers**：流式请求里，宿主交给拦截钩子的是上游响应头**原文**，并不等于客户端实际收到的——CPA 只有在 `passthrough-headers: true` 时才会（过滤逐跳头后）下发它们，默认关闭。插件会尽力读取 CPA 工作目录下的 `config.yaml` 来判断该开关，并在界面上如实标注"未下发 / 已下发 / 未知"，不把"拦截点所见"当成"客户端所得"。

宿主侧的限制，插件无法绕过：

- **发往渠道的请求头拿不到**：渠道密钥、伪装头由执行器内部拼装，任何钩子都不暴露。
- **同协议直通**（如 Claude 客户端 → Claude 协议的中转）时宿主不走翻译层，`normalize_before` 不触发。此时 ④ 的内容就是上游原文，安全检查自动改用它。
- **到不了渠道的请求完全不可见**：模型名解析不出提供商（`unknown provider for model …`）、客户端 API key 无效等，宿主在调用任何插件钩子之前就返回了。这类问题只能看 CPA 自己的日志。
- `normalize_before` 与 `usage.handle` 不带 RequestID。插件用请求体指纹（长度 + 首尾片段）和"模型 + 开始时间"做关联；关联不上的分片仍会并入字段图谱，数量显示在设置页。

## 安全与隐私

- 界面外壳走宿主的 resource 路由，宿主对它不鉴权，所以它是**不含任何数据的静态页面**；全部数据接口在 `/v0/management/cpa-inspector/*` 下，由宿主用管理密钥鉴权。
- 页面不加载任何外部资源，CSP 为 `default-src 'none'`；所有抓取内容一律以 `textContent` 渲染——模型响应是不可信输入。
- 请求头里的凭据在落盘前脱敏（`sk-loc••••test (13 chars)`）；发现项里的机密证据始终打码。
- **`data_dir` 里保存着完整的对话正文**，不脱敏。文件权限为 0600，请按敏感数据对待，并留意 `max_records` / `max_disk_mb`。
- 界面里的"凭据"（如 `codex:apikey:3f9a1c0e7b52`）是宿主生成的稳定标识：对 key、base-url 等做 SHA-256 后取前 12 位，不可反推，可以放心截图。

## 性能开销

- 宿主的插件调用是同步的 cgo + JSON。流式响应里，宿主会在**每个分片**都把完整请求体序列化给 `normalize_before`。插件侧用快速路径跳过了这部分解码，但宿主侧的序列化成本省不掉。长上下文、高并发下如有感知，把 `capture_upstream` 设为 `false`。
- 整份请求体的 JSON 解码、形态提取、机密扫描都在请求结束后的后台协程里做，不在转发热路径上。
- 界面每 5 秒轮询一次；数据没变时不触碰 DOM。

## 常见问题

**日志里出现 `plugin … returned invalid metadata or no capabilities`**
宿主要求插件 metadata 的 Name / Version / Author / GitHubRepository 四项非空。用本仓库构建不会遇到；自行改过 `rpc.go` 时注意。

**日志里没有 `plugin loaded`**
依次检查：`plugins.enabled` 与 `plugins.configs.cpa-inspector.enabled` 是否都为 `true`；`.so` 是否在宿主能看到的 `plugins/` 下（Docker 要挂载）；架构是否匹配；宿主是否 CGO 构建。

**界面提示"被前置的访问网关重定向到了登录页"**
`/v0/management/*` 前面有 Cloudflare Access、Authelia 之类的网关。先在同一浏览器完成网关登录（例如打开 `/management.html`），再回到界面。

**请求报错了，插件里却没有记录**
见上文"到不了渠道的请求完全不可见"。一个常见原因：给模型配了 `alias` 之后，对客户端暴露的模型 ID 就变成了别名，原来的 `name` 不再可用；只想改显示名应使用 `display-name`。

**刚装上，漂移类发现很少**
正常，前 `learn_samples` 个请求在建基线。

**出现了误报**
在发现页"确认"即可消除；如果是插件不认识的新协议形态，欢迎提 issue 并附上结构（键名与类型即可，不需要对话内容）。

## 开发

```bash
make test     # go vet + go test -race
make build
```

`dev/` 下有一套本地端到端环境：一个模拟"第三方渠道"的上游（规矩的 Claude 中转，第 5 个请求起灰测新字段；冒充 Claude 的恶意中转；OpenAI 兼容渠道；额度耗尽的渠道）、CPA 配置和流量脚本。

```bash
make build && mkdir -p dev/plugins && cp dist/cpa-inspector.so dev/plugins/
cd dev
node mock-upstream.js &                              # 127.0.0.1:9101
/path/to/cli-proxy-api --config config.e2e.yaml &    # 127.0.0.1:8417
bash traffic.sh
# 打开 http://127.0.0.1:8417/v0/resource/plugins/cpa-inspector/ui ，密钥 mgmt-test-key
```

代码结构：

| 文件 | 职责 |
|---|---|
| `abi.go` | C ABI 导出（唯一的 cgo 文件） |
| `rpc.go` | RPC 结构体镜像、方法分发、注册信息。自行声明结构体而不 import 宿主模块，避免拉入整个 CPA 依赖树 |
| `config.go` | 配置解析；`normalize_before` 入参的快速解析 |
| `capture.go` | 各钩子处理、请求关联（指纹 / usage）、发现项聚合 |
| `finalize.go` | 请求结束后的后台分析与落盘 |
| `sse.go` | SSE 解析与消息重组，按载荷特征自动识别协议 |
| `shape.go` | 字段形态提取、字段图谱、漂移判定 |
| `security.go` | 安全规则、脱敏 |
| `store.go` | 磁盘持久化与保留策略 |
| `api.go` / `ui/index.html` | Management API 与内嵌界面（单文件，无构建步骤、无外部依赖） |

### 自动构建与发版

`.github/workflows/build.yml` **只在 `main` 分支有推送时运行**（仅改文档不触发）；功能分支、PR、tag 都不会触发，合并进 main 之后才构建。每次运行会跑测试，编译两个产物——`amd64`（x86-64，常用）和 `arm64`（ARM），然后：

- 覆盖滚动预发布 `latest`；
- 如果 `rpc.go` 里的 `pluginVersion` 对应的 `vX.Y.Z` 发布还不存在，就创建它（之后不再改动）。

所以发版的方式是：修改 `pluginVersion`，合入 main。

## 许可证

[MIT](LICENSE)
