# mleak — Thunderbird 逐封邮件 OSINT 分析

*语言：[Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md)*

**源代码：** <https://github.com/c0decave/mleak/>

**简介。** mleak 是一个 Thunderbird 扩展，用于对每封邮件进行取证级别的头与正文分析。它会揭示 MUA 指纹、服务器栈、M365 租户数据、中继路径、认证结果和完整性信号 —— 完全离线。

Thunderbird 115+ 的 WebExtension。按单封邮件级别分析头和正文，并以结构化 OSINT 情报形式显示 —— 可以是弹窗，也可以直接内联在邮件正文上方。

- **MUA / 客户端**：基于 `User-Agent`、`Message-ID` 模式、HTML 正文签名、MIME-Version 括注、以及 MIME 边界前缀（Apple-Mail / enig / _000_ / _NextPart_）—— 五条独立信号，相互交叉验证
- **服务器栈**：Gmail · Exchange/M365 · Apple iCloud · Yahoo · 投递标记（Proofpoint / Mimecast / Barracuda）
- **M365 租户 GUID** + **数据中心区域**：无需 whois 即可直接归因组织
- **中继路径**：跳数、外部中继、**内部主机名泄露**（包括单段 NetBIOS / k8s pod 名）、Received 中的**私有 IP**（IPv4 + IPv6 ULA / 链路本地）、逐跳上下文（“10.x.x.x 经 relay.example.com 来自 ws-eve.corp.local”）
- **认证**：SPF / DKIM / DMARC / ARC / BIMI 结果 + DKIM 签名（域、selector、供应商线索）
- **加密**：Enigmail 版本（通过 `X-Enigmail-Version` 或 `enig…` 边界前缀）、OpenPGP/MIME、S/MIME、Autocrypt / Autocrypt-Gossip、OpenPGP 密钥服务器提示、Symantec PGP-Universal、Tutanota、ProtonMail
- **完整性**：缺失的 Date/MID、From↔Sender 不一致、Reply-To 跨域、DKIM h= 覆盖缺口、oversigning
- **时区**：UTC 归一化 + TZ 偏移
- **MIME 结构**：紧凑的树形指纹
- **逐卡片可见性开关**：在选项页中可隐藏七张卡片中的任意一张

**100% 离线。** 无网络访问、无遥测、无外部依赖。原始邮件字节从不离开 Thunderbird 进程。

---

## 安装

### 临时（开发）
1. `工具 → 附加组件与主题 → ⚙ → 调试附加组件 → 载入临时附加组件 …`
2. 从本目录中选择 `manifest.json`。

### 打包
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (当前：0.5.8)
```
然后：`工具 → 附加组件 → ⚙ → 从文件安装附加组件 …` 并选择 XPI。要让 `xpinstall.signatures.required=false` 生效，你的 Thunderbird 构建必须允许此项（发行版构建 Arch / Debian / ESR 通常都允许）。

---

## 使用

**弹窗模式**（默认，也是目前唯一的模式）：点击邮件工具栏中的图标 → 弹窗打开并显示所有情报卡片。内联面板模式仍被关闭，因为一个与布局相关的注入 bug 还在排查中 —— 代码路径已就位，根因修复后只需改一行即可重新启用。

打开设置：`工具 → 附加组件 → mleak → 首选项`。选项：
- 配色方案（自动 / 深色 / 浅色）
- 弹窗宽度（440 / 500 / 600 / 720 px）—— 600 为默认
- 密度（紧凑 / 正常 / 宽松）
- 默认视图（卡片 / JSON）
- 可见卡片（可隐藏七个类别中的任意一项）
- 分析缓存大小 + 立即清空按钮
- 调试日志（可选）+ 日志查看器
- 关于（版本 + 贡献未识别指纹的邀请）

---

## 安全与隐私

| 属性 | 状态 |
|---|---|
| 网络请求 | **无**（无 `fetch`、`XHR`、`sendBeacon`、`WebSocket`） |
| DOM 注入 | **无**（仅使用 `textContent`/`createElement`；无动态值写入的 `innerHTML`） |
| CSP | 严格：`script-src 'self'; object-src 'none'; base-uri 'none'` |
| 权限 | **最小**：仅 `messagesRead` + `storage` + `tabs`（无 `messagesModify`，无 `<all_urls>`） |
| 存储 | 仅在 `storage.local` 中保存 UI 偏好；**无邮件内容** |
| 调试日志 | 可选开启，环形缓冲（最多 500 条，仅状态字符串，无头信息） |
| ReDoS 防护 | 正则匹配前对头值进行长度上限（8 KB）和 Message-ID 上限（1 KB） |

每一行代码都可审计。技术细节、检测器架构、威胁模型和构建说明见 [DEVELOPING.md](DEVELOPING.md)。

---

## 术语

你会在弹窗和内联面板中看到的术语：

- **MUA** —— Mail User Agent；撰写邮件的客户端（Thunderbird、Outlook、Apple Mail 等）。
- **服务器栈** —— 邮件经过的服务器端产品（Gmail、Exchange/M365、Apple iCloud、Yahoo、Proofpoint、Mimecast、Barracuda）。
- **M365 租户** —— Microsoft 365 在外发邮件头中打入的 GUID；可直接定位发件方所属组织，无需 whois。
- **中继路径** —— 邮件经过的外部服务器列表（Received 链中的 `by` 主机），顶部为第一跳。
- **私有 IP 泄露** —— Received 中暴露的 RFC 1918 地址（10.x.x.x、172.16-31.x.x、192.168.x.x）；泄露发件方内网。
- **内部主机名泄露** —— Received 中的 `.local` / `.corp` / `.internal` / `.lan` 风格主机名；泄露发件方内部网络。
- **认证结果** —— 接收方报告的 SPF、DKIM、DMARC、ARC、BIMI 通过/失败状态。
- **DKIM oversigning** —— 在 DKIM 签名的 `h=` 标签中**多次**列出某个头名（例如 `h=from:from:subject:subject`）。用于抵御头注入攻击：如果后续中继添加了第二个 `From:`，签名会被破坏，而不是静默验证一个伪造头。
- **DKIM h= 覆盖缺口** —— 安全相关头（`From`、`Subject`、`Reply-To`、`Date`、`Message-ID`）**未**在签名 `h=` 标签中列出，意味着该头可在传输中被修改而不破坏签名。
- **跳数** —— 链中 Received 头的数量。相对基线的突变往往表明转发/中继重写。
- **时序异常** —— Received 时间戳未按自顶向下单调递减；通常是中继时钟漂移，偶尔是链篡改。
- **完整性标志** —— 结构上的异常：缺失 Date/Message-ID、From↔Sender 不一致、Reply-To 跨域。
- **Enigmail** —— Thunderbird 的 PGP 附加组件。通过 `X-Enigmail-Version` *或* `-------enig…` MIME 边界前缀检测（即使头被剥离也能识别）。
- **OpenPGP/MIME** —— RFC 3156 加密/签名 multipart；通过 `multipart/{encrypted,signed}` + `protocol=application/pgp-*` 检测。
- **S/MIME** —— RFC 2633 / PKCS#7 签名或加密；通过 `application/(x-)?pkcs7-*` 内容类型检测。
- **Autocrypt** —— RFC 草案的自动密钥交换头；存在即为 MUA 能力信号。
- **边界 MUA 提示** —— MUA 会在 MIME 边界中打入产品特定前缀（`Apple-Mail=`、`_000_`、`_NextPart_`、`----=_Part_`）。由于边界在中继重写后仍保留，是一种很有用的 MUA 指纹 ——*即便正文被加密*、HTML 扫描器无从下手时也能用。

---

## 版本

- **0.5.8** —— 采用 **MPL-2.0** 许可（LICENSE + 每个源文件的 SPDX 头）；i18n 扩展至九种语言（新增 zh、hi、pt）；用户 README 现提供七种语言（DE/EN/ES/ZH/HI/PT/PL）；LICENSE 随 XPI 一同打包。
- **0.5.6** —— 用户文档与开发者文档分离；XPI 附带全部用户 README；发布流水线（`scripts/release.sh`）仅生成 `.xpi` + `.sha256`。
- **0.5.5** —— XPI 在 index 旁附带 `README_DE.md` / `README_EN.md` / `README_ES.md`；回归测试强制该布局。
- **0.5.4** —— 红队清理：`inline/inline.js` 的 on-message 载荷形状校验与 `background.js` 对称；TB 二进制通过绝对路径解析，减少一项环境 PATH 依赖。
- **0.5.3** —— 纵深防御加固：`lib/i18n.js` 中的 `SAFE_HTML_KEYS` 白名单把关每个 `data-i18n-html` 键；manifest 版本在写入 About 卡片 innerHTML 前格式校验；`runtime.onMessage` 入口对 `msg.type` + `msg.messageId` 做类型校验。
- **0.5.2** —— 静态分析发现的两个正确性问题：`mid_patterns.js` 的 `domain.endsWith("gmail.com")` 改为精确或子域检查；`ua_parser.js` 的 Mutt 正则字符类简化（重叠范围）。
- **0.5.1** —— 内联模式 UI 暂时关闭（布局相关注入 bug）；检测器失败走可选开启的调试日志；启动 IIFE 捕获未处理的 promise 拒绝。通过安全审计：无网络、无混淆、无后门式代码，`messages.getFull` 单一调用点由我们自己的消息类型把关。
- **0.5.0** —— 新增 `crypto_headers.js` 检测器（Enigmail、OpenPGP/MIME、S/MIME、Autocrypt、网关头、边界前缀 MUA 提示）。Received 链修复：by 括注解析、`from [IP]` HELO 纯 IP 提取、带 sentinel 过滤的单段内部主机名启发、IPv6 私有范围（ULA / 链路本地 / 映射）。MIME-Version 括注作为次要 MUA 来源。修复外部中继循环中的 `ReferenceError`。
- **0.4.2** —— by 侧括注捕获 + 单段主机名检测（1&1 Kubernetes pod 名 / NetBIOS 泄露类）。
- **0.4.1** —— 内联模式生命周期在 `onMessageDisplayed` + `tabs.executeScript` 上重写，附带详细 dlog（试图让内联模式稳定工作；部分成功 —— 在 0.5.1 中仍被关闭）。
- **0.4.0** —— 逐卡片可见性开关（7 卡片）、泄露行的逐跳上下文、垂直中继路径、EN/DE/ES 术语表、带贡献 CTA 的 About 区。
- **0.3.0** —— 六种语言的 i18n（en/de/es/fr/pl/it）、信封加放大镜图标、多语言 README、`default_locale` 设置。
- **0.2.0** —— 内联模式（初次尝试）、设置页、响应式弹窗、安全加固（长度上限、ReDoS 防护）、SVG logo、更名为 *mleak*。
- **0.1.0** —— 首次发布：弹窗 + 9 个检测器模块。

---

## 贡献未知 MUA / 服务器指纹

发现扩展**无法归类**的邮件 —— 且你已经知道它来自哪个客户端或服务器栈？请将相关头发给我们。这些贡献正是检测器目录得以扩充的方式。

请发送：

1. 打开邮件，视图 → 消息源（或 Ctrl+U）。
2. 复制顶部的头块，直到（并包括）第一个空行 —— 大致是从 `Received:` 到 `Message-ID:`、`User-Agent:`，加上其他看起来有意思的头。
3. 说明你知道（或怀疑）它来自哪个客户端 / 网页邮箱 / 中继产品。
4. 如需可遮盖个人地址；**绝不要遮盖 `Received`、`Message-ID`、`X-*` 或认证头** —— 这些是我们需要的。
5. 邮件：**mlux@undisclose.de**，主题以 `mleak-sample` 开头。

如果你更习惯 Git：请在 **<https://github.com/c0decave/mleak/>** 用同样的信息开 issue 或 PR。

---

~ Proudly "agentic engineered" with Claude ~

## 许可证

基于 **Mozilla Public License 2.0** —— 见 [LICENSE](LICENSE)。

MPL-2.0 是一种文件级 copyleft 许可证：对 MPL 文件的修改必须保持 MPL，但你可以自由地将 mleak 与其他许可证（包括专有许可证）下的代码组合成 Larger Work。该许可证含明确的专利授予条款。

联系方式：mlux@undisclose.de
