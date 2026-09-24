package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// 发现项（finding）：安全规则与漂移检测的统一输出。
// 严重级别：critical（疑似篡改/注入）> warn（需要人工确认）> notice（灰测/漂移信号）> info（备查）。

const (
	sevCritical = "critical"
	sevWarn     = "warn"
	sevNotice   = "notice"
	sevInfo     = "info"

	catSecurity  = "security"  // 渠道可信度：偷换、注入、篡改
	catPrivacy   = "privacy"   // 我方外泄：密钥随请求发给第三方
	catIntegrity = "integrity" // 协议完整性：截断、事件错序
	catDrift     = "drift"     // 字段漂移 / 灰测信号
	catCost      = "cost"      // 缓存与计费：本可避免的重复计费
)

type finding struct {
	Key       string    `json:"key"` // 聚合键：同一问题重复出现只累加计数
	Severity  string    `json:"severity"`
	Category  string    `json:"category"`
	Rule      string    `json:"rule"`
	Title     string    `json:"title"`
	Detail    string    `json:"detail,omitempty"`
	Evidence  string    `json:"evidence,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	Path      string    `json:"path,omitempty"`
	Model     string    `json:"model,omitempty"`
	Channel   string    `json:"channel,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Time      time.Time `json:"time"`
}

// aggFinding 是跨请求聚合后的发现项。
type aggFinding struct {
	finding
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	FirstReq  string    `json:"first_request_id,omitempty"`
	Acked     bool      `json:"acked,omitempty"`
}

func findingKey(parts ...string) string {
	sum := sha1.Sum([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

var severityRank = map[string]int{sevInfo: 1, sevNotice: 2, sevWarn: 3, sevCritical: 4}

// ---------- 头部脱敏 ----------

var sensitiveHeaders = map[string]bool{
	"authorization": true, "proxy-authorization": true, "x-api-key": true, "api-key": true,
	"x-goog-api-key": true, "cookie": true, "set-cookie": true, "x-management-key": true,
	"openai-organization": false,
}

func isSensitiveHeader(name string) bool {
	lower := strings.ToLower(name)
	return sensitiveHeaders[lower] || strings.Contains(lower, "token") || strings.Contains(lower, "secret")
}

// redactHeaders 返回脱敏后的头部副本：凭据类头部只保留首尾几位。
func redactHeaders(h http.Header) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for name, values := range h {
		masked := isSensitiveHeader(name)
		copied := make([]string, len(values))
		for i, v := range values {
			if masked {
				v = maskSecret(v)
			}
			copied[i] = v
		}
		out[name] = copied
	}
	return out
}

func maskSecret(s string) string {
	prefix := ""
	if i := strings.IndexByte(s, ' '); i > 0 && i < 10 { // "Bearer xxx"
		prefix, s = s[:i+1], s[i+1:]
	}
	if len(s) <= 12 {
		return prefix + strings.Repeat("•", len(s))
	}
	return fmt.Sprintf("%s%s••••%s (%d chars)", prefix, s[:6], s[len(s)-4:], len(s))
}

// ---------- 规则：请求体中的机密 ----------

type secretPattern struct {
	name    string
	literal []byte // 廉价预筛：不含该字面量就不跑正则
	re      *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"私钥 (PEM)", []byte("PRIVATE KEY-----"), regexp.MustCompile(`-----BEGIN [A-Z ]{0,24}PRIVATE KEY-----`)},
	{"AWS Access Key", []byte("AKIA"), regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub Token", []byte("gh"), regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"Anthropic API Key", []byte("sk-ant-"), regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{24,}`)},
	{"OpenAI 风格 API Key", []byte("sk-"), regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}`)},
	{"Google API Key", []byte("AIza"), regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Slack Token", []byte("xox"), regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{20,}`)},
	{"Stripe Live Key", []byte("_live_"), regexp.MustCompile(`\b[sr]k_live_[0-9a-zA-Z]{24,}`)},
	{"JWT", []byte("eyJ"), regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{12,}\.eyJ[A-Za-z0-9_\-]{12,}\.[A-Za-z0-9_\-]{12,}`)},
	{"带口令的连接串", []byte("://"), regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@"'\\]{1,64}:[^\s@"'\\]{4,128}@[A-Za-z0-9.\-]+`)},
}

const maxSecretFindings = 8

// pemBlock 覆盖整个私钥块。secretPatterns 里的 PEM 规则只匹配 BEGIN 行，够检测、不够打码；
// 证据常被截断，缺 END 行时一直遮到文本末尾。
var pemBlock = regexp.MustCompile(`-----BEGIN [A-Z ]{0,24}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]{0,24}PRIVATE KEY-----|$)`)

// secretPrefix 匹配以已知机密前缀开头、但不一定完整的 token。字段示例只保留前 96 字节，
// 被截断的半截密钥（或超出打码窗口的长 JWT）已认不出完整形态，但仍是密钥的一部分。
// 示例只用于展示，宁可多遮。
var secretPrefix = regexp.MustCompile(`\b(?:sk-|AKIA|gh[pousr]_|github_pat_|AIza|xox[baprs]-|[sr]k_live_|eyJ)[A-Za-z0-9_\-.]{4,}|\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@"'\\]{1,64}:[^\s@"'\\]+`)

// maskExample 给要长期留存的示例文本打码：完整机密按常规规则遮盖，残缺的机密前缀也一并遮盖。
func maskExample(text string) string {
	return secretPrefix.ReplaceAllStringFunc(maskSecretsIn(text), maskSecret)
}

// maskSecretsIn 把文本里命中机密模式的片段打码。发现项的证据来自请求 / 响应原文
// （字段示例、工具入参…），聚合后长期留存，不能把机密原样带进去。
func maskSecretsIn(text string) string {
	if strings.Contains(text, "PRIVATE KEY-----") {
		text = pemBlock.ReplaceAllStringFunc(text, func(block string) string {
			return fmt.Sprintf("-----BEGIN PRIVATE KEY----- •••• (%d chars)", len(block))
		})
	}
	for _, p := range secretPatterns {
		if strings.Contains(text, string(p.literal)) {
			text = p.re.ReplaceAllStringFunc(text, maskSecret)
		}
	}
	return text
}

func scanSecrets(body []byte, base finding) []finding {
	var out []finding
	seen := make(map[string]bool)
	for _, p := range secretPatterns {
		if !bytes.Contains(body, p.literal) {
			continue
		}
		for _, match := range p.re.FindAll(body, 4) {
			text := string(match)
			if seen[text] || len(out) >= maxSecretFindings {
				continue
			}
			seen[text] = true
			f := base
			f.Severity, f.Category, f.Rule = sevWarn, catPrivacy, "secret-in-request"
			f.Title = "请求体中含疑似机密：" + p.name
			f.Detail = "该内容会随对话上下文原样发给上游渠道。若渠道为第三方，应视为已泄露并考虑轮换。"
			f.Evidence = maskSecret(text)
			f.Key = findingKey(f.Rule, p.name, text)
			out = append(out, f)
		}
	}
	return out
}

// ---------- 规则：模型偷换 ----------

var vendorMarkers = []struct{ vendor, marker string }{
	{"anthropic", "claude"}, {"openai", "gpt"}, {"openai", "o1"}, {"openai", "o3"}, {"openai", "o4"}, {"openai", "codex"},
	{"google", "gemini"}, {"google", "gemma"}, {"zhipu", "glm"}, {"alibaba", "qwen"}, {"deepseek", "deepseek"},
	{"moonshot", "kimi"}, {"moonshot", "moonshot"}, {"xai", "grok"}, {"meta", "llama"}, {"mistral", "mistral"},
	{"minimax", "minimax"}, {"bytedance", "doubao"}, {"meta", "muse"},
}

func modelVendor(model string) string {
	m := strings.ToLower(model)
	for _, v := range vendorMarkers {
		if strings.Contains(m, v.marker) {
			return v.vendor
		}
	}
	return ""
}

var modelNoise = regexp.MustCompile(`(?:^models/|^[a-z0-9\-]+/|[@:\-]?\d{8}$|-\d{4}-\d{2}-\d{2}$|-latest$|\[[^\]]*\]$|-v\d+:\d+$)`)

// normalizeModel 去掉供应商前缀、日期后缀等噪声，便于比较 "claude-sonnet-4-5" 与 "claude-sonnet-4-5-20250929"。
func normalizeModel(model string) string {
	m := strings.ToLower(strings.TrimSpace(model))
	for i := 0; i < 3; i++ {
		next := modelNoise.ReplaceAllString(m, "")
		if next == m || next == "" {
			break
		}
		m = next
	}
	return strings.NewReplacer(".", "-", "_", "-").Replace(m)
}

// modelTier 匹配表示"另一档模型"的后缀词：gpt-4o 与 gpt-4o-mini 不是同一个模型。
var modelTier = regexp.MustCompile(`(?:^|-)(?:mini|nano|lite|small|tiny|micro|flash|haiku|air|fast|turbo|max|pro|plus|ultra)(?:-|$)`)

// sameModelFamily：一方是另一方的前缀、且多出来的后缀不含档位词时视为同一模型
// （渠道常给模型名追加 -preview、-thinking、推理强度等后缀）。
func sameModelFamily(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	return strings.HasPrefix(b, a) && !modelTier.MatchString(b[len(a):])
}

// checkModel 比较"发往上游的模型"与"上游自报的模型"。返回 nil 表示一致。
func checkModel(requested, reported string, base finding) *finding {
	if requested == "" || reported == "" {
		return nil
	}
	a, b := normalizeModel(requested), normalizeModel(reported)
	if a == b || sameModelFamily(a, b) {
		return nil
	}
	f := base
	f.Category, f.Rule = catSecurity, "model-mismatch"
	f.Severity = sevWarn
	f.Title = "上游自报模型与请求模型不一致"
	f.Detail = "渠道可能做了模型映射、降级或偷换。"
	if va, vb := modelVendor(requested), modelVendor(reported); va != "" && vb != "" && va != vb {
		f.Severity = sevCritical
		f.Title = "上游自报模型来自另一家厂商"
		f.Detail = fmt.Sprintf("请求的是 %s 系模型，响应自报为 %s 系模型：渠道很可能用其它模型冒充。", va, vb)
	}
	f.Evidence = fmt.Sprintf("请求 %s → 响应 %s", requested, reported)
	f.Key = findingKey(f.Rule, a, b, base.Channel)
	return &f
}

// ---------- 规则：未声明的工具调用 / 危险的工具入参 ----------

// declaredTools 从请求体里收集已声明的工具名（兼容 Claude / Chat / Responses / Gemini）。
// 声明位置有两种：顶层 tools；以及新版 Codex 放在 input[] 里的 {"type":"additional_tools","tools":[...]}。
// 工具还可能按命名空间嵌套（{"type":"namespace","name":"functions","tools":[...]}）。
func declaredTools(req any) map[string]bool {
	obj, ok := req.(map[string]any)
	if !ok {
		return nil
	}
	if inner, ok := obj["request"].(map[string]any); ok { // Gemini CLI 外层包装
		obj = inner
	}
	names := make(map[string]bool)
	collectTools(asSlice(obj["tools"]), "", names, 0)
	for _, it := range asSlice(obj["input"]) {
		if item, ok := it.(map[string]any); ok {
			collectTools(asSlice(item["tools"]), "", names, 0)
		}
	}
	delete(names, "")
	return names
}

func collectTools(tools []any, namespace string, names map[string]bool, depth int) {
	if depth > 4 {
		return
	}
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		name := asString(tool["name"])
		if nested := asSlice(tool["tools"]); len(nested) > 0 { // 命名空间 / 工具集
			collectTools(nested, name, names, depth+1)
			continue
		}
		add := func(n string) {
			if n == "" {
				return
			}
			names[n] = true
			if namespace != "" { // 模型可能用 限定名 调用
				names[namespace+"."+n] = true
				names[namespace+"__"+n] = true
			}
		}
		add(name)
		if name == "" {
			add(asString(tool["type"])) // 无名的服务端工具以 type 标识（web_search_preview 等）
		}
		if fn, ok := tool["function"].(map[string]any); ok {
			add(asString(fn["name"]))
		}
		for _, key := range []string{"functionDeclarations", "function_declarations"} {
			for _, d := range asSlice(tool[key]) {
				if decl, ok := d.(map[string]any); ok {
					add(asString(decl["name"]))
				}
			}
		}
	}
}

var dangerousPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"下载后直接管道执行", regexp.MustCompile(`(?i)\b(?:curl|wget|fetch)\b[^|;&\n]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`)},
	{"base64 解码后执行", regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)[^|\n]{0,120}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`)},
	{"反弹 shell", regexp.MustCompile(`(?i)(?:/dev/tcp/\d|\bnc(?:at)?\b[^\n]{0,60}\s-e\s|\bbash\s+-i\s+>&|\bsocat\b[^\n]{0,80}exec:)`)},
	{"PowerShell 远程加载执行", regexp.MustCompile(`(?i)(?:\biex\b|invoke-expression)[^\n]{0,120}(?:downloadstring|invoke-webrequest|\biwr\b|net\.webclient)`)},
	{"写入 SSH 授权/定时任务", regexp.MustCompile(`(?i)(?:>>?\s*~?/?[^\s]*\.ssh/authorized_keys|\bcrontab\s+-[^l\s]|>>?\s*/etc/cron)`)},
	{"读取凭据文件并外发", regexp.MustCompile(`(?i)(?:\.ssh/id_[a-z0-9]+|\.aws/credentials|\.netrc|\.npmrc|\.env\b)[^\n]{0,200}\b(?:curl|wget|nc|scp)\b`)},
	{"破坏性删除", regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:/|~|\$HOME)(?:\s|$|\*)`)},
}

func checkToolCalls(side string, msg *message, declared map[string]bool, hasToolInfo bool, base finding) []finding {
	var out []finding
	calls := msg.toolCalls()
	// 请求里一个工具声明都没找到：多半是插件还不认识的声明方式，而不是渠道注入。
	// 此时无从校验，只给一条低级别提示，绝不报"严重"。
	if hasToolInfo && len(declared) == 0 && len(calls) > 0 {
		f := base
		f.Severity, f.Category, f.Rule = sevNotice, catSecurity, "tool-declarations-not-found"
		f.Title = "响应含工具调用，但请求中未找到任何工具声明，无法校验"
		f.Detail = "可能是客户端换了新的工具声明方式（插件尚不认识）。若确认如此请反馈；若请求确实不该带工具，则需警惕（" + side + "）。"
		f.Evidence = calls[0].Name
		f.Key = findingKey(f.Rule, side, base.Model)
		out = append(out, f)
		hasToolInfo = false
	}
	for _, call := range calls {
		if hasToolInfo && call.Name != "" && !declared[call.Name] && call.Type == "tool_use" {
			f := base
			f.Severity, f.Category, f.Rule = sevCritical, catSecurity, "undeclared-tool"
			f.Title = "响应调用了请求中未声明的工具"
			f.Detail = "模型只应调用请求里声明过的工具。未声明的工具调用可能是渠道注入的指令（" + side + "）。"
			f.Evidence = call.Name + " " + truncate(call.Input, 200)
			f.Key = findingKey(f.Rule, call.Name, base.Channel)
			out = append(out, f)
		}
		for _, p := range dangerousPatterns {
			if loc := p.re.FindStringIndex(call.Input); loc != nil {
				f := base
				f.Severity, f.Category, f.Rule = sevWarn, catSecurity, "dangerous-tool-input"
				f.Title = "工具调用入参含高危命令模式：" + p.name
				f.Detail = "可能是模型的正常行为（如安装脚本），也可能是被篡改的响应。请结合上下文确认（" + side + "）。"
				f.Evidence = call.Name + ": " + truncate(call.Input[max(0, loc[0]-40):], 240)
				f.Key = findingKey(f.Rule, p.name, call.Name, truncate(call.Input[loc[0]:loc[1]], 120))
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// ---------- 规则：Claude 协议指纹 ----------

// claudeMsgID 是历史上官方后端的消息 ID 形态。注意这只是经验：官方格式可能调整，
// 不少中转（one-api / new-api 等）也会重写 ID，所以单凭它不能判定后端真假。
var claudeMsgID = regexp.MustCompile(`^msg_(?:01[A-Za-z0-9]{20,}|bdrk_[A-Za-z0-9]+|vrtx_[A-Za-z0-9]+)$`)

// claudeProvenance 依据消息 ID 前缀给出来源标签；认不出就不贴标签（不下"非官方"这种结论）。
func claudeProvenance(id string) string {
	switch {
	case strings.HasPrefix(id, "msg_bdrk_"):
		return "AWS Bedrock"
	case strings.HasPrefix(id, "msg_vrtx_"):
		return "Google Vertex"
	}
	return ""
}

func checkClaudeFingerprint(msg *message, base finding) []finding {
	if msg.Format != fmtClaude || msg.Error != "" {
		return nil
	}
	var out []finding
	unsigned := false
	for _, b := range msg.Blocks {
		if msg.Overflow { // 重组中途停止：签名可能在没采集的尾部里，不能据此判缺失
			break
		}
		if b.Type == "thinking" && b.SignatureLen == 0 && b.Text != "" {
			unsigned = true
			f := base
			f.Severity, f.Category, f.Rule = sevWarn, catSecurity, "thinking-no-signature"
			f.Title = "thinking 块缺少 signature"
			f.Detail = "官方 Claude 的 thinking 块必带加密签名（多轮工具调用时需原样回传）。缺失通常说明后端不是真正的 Claude，或渠道改写了响应。"
			f.Key = findingKey(f.Rule, base.Model, base.Channel)
			out = append(out, f)
			break
		}
	}
	if msg.ID != "" && !claudeMsgID.MatchString(msg.ID) {
		f := base
		f.Category, f.Rule = catSecurity, "claude-id-format"
		// ID 本身是弱证据：只有和"thinking 无签名"同时出现才值得警告，否则仅备查。
		f.Severity = sevInfo
		if unsigned {
			f.Severity = sevWarn
		}
		f.Title = "Claude 消息 ID 不是 msg_01… 形态"
		f.Detail = "历史上官方后端的 ID 形如 msg_01…（直连）、msg_bdrk_…（Bedrock）、msg_vrtx_…（Vertex）。中转常会重写 ID，官方格式也可能调整，单凭这一点不能说明后端不是 Claude，请结合 thinking 签名与 usage 字段判断。该渠道的 ID 形态日后若发生变化，会另以漂移报告。"
		f.Evidence = truncate(msg.ID, 80)
		f.Key = findingKey(f.Rule, idForm(msg.ID), base.Channel)
		out = append(out, f)
	}
	return out
}

var idPrefix = regexp.MustCompile(`^(?:[a-z]+[_-])+`)

// idForm 把 ID 概括成稳定的形态：字母前缀 + 是否以 01 开头 + 随机段长度，如 "msg_01…(22)"、"msg_…(24)"、"chatcmpl-…(29)"。
func idForm(id string) string {
	prefix := idPrefix.FindString(id)
	tail, mark := id[len(prefix):], "…"
	if strings.HasPrefix(tail, "01") {
		mark = "01…"
	}
	return fmt.Sprintf("%s%s(%d)", prefix, mark, len(tail))
}

// fingerprintEntries 提取"后端指纹"，按渠道并入字段图谱：形态一旦变化（换后端、开始/停止重写 ID、
// thinking 签名从有到无）就会以漂移报告。这比写死"官方应该长什么样"可靠。
func fingerprintEntries(msg *message) []shapeEntry {
	if msg == nil || msg.Error != "" || msg.Overflow { // 重组不完整的消息不进指纹基线
		return nil
	}
	var out []shapeEntry
	if msg.ID != "" {
		form := idForm(msg.ID)
		out = append(out, shapeEntry{Path: "id_form=" + form, Type: "enum", Example: truncate(msg.ID, 48)})
	}
	if msg.Echo != nil { // 渠道注入的系统提示词也是后端指纹：换了一份就以漂移报告
		form := "none"
		if msg.Echo.InstructionsSHA != "" {
			form = fmt.Sprintf("%s(%d)", msg.Echo.InstructionsSHA, msg.Echo.InstructionsLen)
		}
		out = append(out, shapeEntry{Path: "echo_instructions=" + form, Type: "enum", Example: truncate(msg.Echo.InstructionsHead, 96)})
	}
	for _, b := range msg.Blocks {
		if b.Type == "thinking" && b.Text != "" {
			state := "present"
			if b.SignatureLen == 0 {
				state = "absent"
			}
			out = append(out, shapeEntry{Path: "thinking_signature=" + state, Type: "enum", Example: state})
			break
		}
	}
	return out
}

// ---------- 规则：输入 token 虚高 ----------

// checkTokenInflation：上游计费的输入 token 数不应远超请求体字节数能容纳的量。
// 各家分词器下 1 token 至少约 1.5 字节（CJK 最密），留足余量后仍超出，
// 说明渠道可能在你的请求之外注入了隐藏提示词，或计费数字被虚报。
func checkTokenInflation(msg *message, upstreamReqBytes int, base finding) *finding {
	reported := msg.inputTokens()
	if reported <= 0 || upstreamReqBytes <= 0 {
		return nil
	}
	ceiling := int64(float64(upstreamReqBytes)/1.5) + 3000
	if reported <= ceiling {
		return nil
	}
	f := base
	f.Severity, f.Category, f.Rule = sevWarn, catSecurity, "input-token-inflation"
	f.Title = "上游计费的输入 token 远超请求体实际大小"
	f.Detail = "可能被注入了隐藏系统提示词，或 usage 被虚报。"
	f.Evidence = fmt.Sprintf("请求体 %d 字节（理论上限约 %d token），上游报告 %d token", upstreamReqBytes, ceiling, reported)
	f.Key = findingKey(f.Rule, base.Model, base.Channel)
	return &f
}

// ---------- 规则：明文上游 / 响应中的外部域名 ----------

func checkBaseURL(baseURL string, base finding) *finding {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "http" {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" || strings.HasPrefix(host, "127.") || strings.HasPrefix(host, "10.") || strings.HasPrefix(host, "192.168.") || host == "::1" || !strings.Contains(host, ".") {
		return nil
	}
	f := base
	f.Severity, f.Category, f.Rule = sevWarn, catSecurity, "plaintext-upstream"
	f.Title = "上游渠道使用明文 HTTP"
	f.Detail = "请求体、响应与渠道密钥在公网上未加密传输，链路上任何节点都可窃听或篡改。"
	f.Evidence = u.Scheme + "://" + u.Host
	f.Key = findingKey(f.Rule, u.Host)
	return &f
}

var urlPattern = regexp.MustCompile(`https?://([A-Za-z0-9](?:[A-Za-z0-9\-]{0,62}\.)+[A-Za-z]{2,24})`)

// checkNewDomains：响应正文/工具入参里出现、而请求上下文里从未出现过的域名。
// 模型本来就会提到文档链接，所以只是 info 级备查；它的价值在于聚合视图能暴露渠道插入的推广链接。
func checkNewDomains(msg *message, requestBody []byte, base finding) []finding {
	seen := make(map[string]bool)
	var out []finding
	lowerReq := bytes.ToLower(requestBody)
	for _, b := range msg.Blocks {
		if b.Type == "thinking" {
			continue
		}
		for _, text := range []string{b.Text, b.Input} {
			for _, m := range urlPattern.FindAllStringSubmatch(text, 32) {
				domain := strings.ToLower(m[1])
				if seen[domain] || bytes.Contains(lowerReq, []byte(domain)) {
					continue
				}
				seen[domain] = true
				f := base
				f.Severity, f.Category, f.Rule = sevInfo, catSecurity, "new-domain"
				f.Title = "响应中出现请求上下文之外的域名"
				f.Evidence = domain
				f.Key = findingKey(f.Rule, domain)
				out = append(out, f)
				if len(out) >= 6 {
					return out
				}
			}
		}
	}
	return out
}

// ---------- 漂移事件 → 发现项 ----------

var driftTitles = map[string]string{
	"new_field":           "出现基线之外的新字段",
	"new_enum":            "出现基线之外的新枚举值",
	"new_field_for_model": "该模型开始返回此前从未带过的字段",
	"missing_field":       "该模型此前必现的字段缺失",
	"type_change":         "字段类型发生变化",
}

func driftFinding(ev driftEvent, base finding) finding {
	f := base
	f.Category, f.Rule = catDrift, ev.Kind
	f.Severity = sevNotice
	if strings.HasPrefix(ev.Scope, scopeClientRequest) || strings.HasPrefix(ev.Scope, scopeUpstreamRequest) {
		f.Severity = sevInfo // 请求侧变化源自自己的客户端升级，仅备查
	}
	f.Title = driftTitles[ev.Kind]
	f.Scope, f.Path, f.Model = ev.Scope, ev.Path, ev.Model
	switch ev.Kind {
	case "type_change":
		f.Evidence = fmt.Sprintf("%s：%s → %s（示例 %s）", ev.Path, ev.Prior, ev.Type, ev.Example)
	case "missing_field":
		f.Evidence = fmt.Sprintf("%s（%s）", ev.Path, ev.Type)
	default:
		f.Evidence = fmt.Sprintf("%s : %s = %s", ev.Path, ev.Type, ev.Example)
	}
	f.Key = findingKey(f.Rule, ev.Scope, ev.Path, ev.Model)
	if ev.Kind == "new_field" || ev.Kind == "new_enum" {
		f.Key = findingKey(f.Rule, ev.Scope, ev.Path)
	}
	return f
}

func sortFindings(list []finding) {
	sort.SliceStable(list, func(i, j int) bool {
		return severityRank[list[i].Severity] > severityRank[list[j].Severity]
	})
}
