package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// 请求回显比对：OpenAI Responses 协议的上游会在 response 对象里回显实际生效的请求参数
// （instructions、tools、parallel_tool_calls、reasoning…）。把它与真正发出去的请求对比，
// 就能看出中转渠道有没有改写请求——注入系统提示词、加工具、降推理强度。这比看模型名可靠。

const echoHeadLen = 600

type requestEcho struct {
	instructions      string
	InstructionsLen   int      `json:"instructions_len"`
	InstructionsSHA   string   `json:"instructions_sha,omitempty"`
	InstructionsHead  string   `json:"instructions_head,omitempty"`
	Tools             []string `json:"tools"`
	ParallelToolCalls *bool    `json:"parallel_tool_calls,omitempty"`
	ReasoningEffort   string   `json:"reasoning_effort,omitempty"`
	Verbosity         string   `json:"verbosity,omitempty"`
	ServiceTier       string   `json:"service_tier,omitempty"`
	MaxOutputTokens   *int64   `json:"max_output_tokens,omitempty"`
}

type echoDiff struct {
	Param    string `json:"param"`
	Sent     string `json:"sent"`
	Echoed   string `json:"echoed"`
	Note     string `json:"note,omitempty"`
	Severity string `json:"severity"`
	kind     string
	keyPart  string
}

// captureEcho 从 response 对象提取回显。只有带 instructions 或 tools 键的对象才算回显。
func captureEcho(resp map[string]any) *requestEcho {
	_, hasInstructions := resp["instructions"]
	_, hasTools := resp["tools"]
	if !hasInstructions && !hasTools {
		return nil
	}
	e := &requestEcho{Tools: []string{}}
	switch ins := resp["instructions"].(type) {
	case string:
		e.instructions = ins
	case []any: // 也可能以 input item 列表的形式回显
		e.instructions = itemsText(ins)
	}
	if e.instructions != "" {
		sum := sha256.Sum256([]byte(e.instructions))
		e.InstructionsLen, e.InstructionsSHA = len(e.instructions), hex.EncodeToString(sum[:5])
		e.InstructionsHead = truncate(e.instructions, echoHeadLen)
	}
	for _, t := range asSlice(resp["tools"]) {
		if id := toolIdent(t); id != "" {
			e.Tools = append(e.Tools, id)
		}
	}
	sort.Strings(e.Tools)
	if b, ok := resp["parallel_tool_calls"].(bool); ok {
		e.ParallelToolCalls = &b
	}
	e.ReasoningEffort = asString(nestedGet(resp, "reasoning", "effort"))
	e.Verbosity = asString(nestedGet(resp, "text", "verbosity"))
	e.ServiceTier = asString(resp["service_tier"])
	if n, ok := resp["max_output_tokens"].(json.Number); ok {
		v, _ := n.Int64()
		e.MaxOutputTokens = &v
	}
	return e
}

func toolIdent(t any) string {
	tool, ok := t.(map[string]any)
	if !ok {
		return ""
	}
	typ, name := asString(tool["type"]), asString(tool["name"])
	if name == "" {
		if fn, ok := tool["function"].(map[string]any); ok {
			name = asString(fn["name"])
		}
	}
	if name == "" {
		return typ
	}
	return typ + ":" + name
}

// itemsText 拼出 input item 列表里的文本。
func itemsText(items []any) string {
	var sb strings.Builder
	for _, it := range items {
		item, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := item["content"].(string); ok {
			sb.WriteString(s)
		}
		for _, p := range asSlice(item["content"]) {
			if part, ok := p.(map[string]any); ok {
				sb.WriteString(asString(part["text"]))
			}
		}
	}
	return sb.String()
}

// sentPromptTexts 收集请求里已有的提示词：instructions，以及 developer / system 角色的消息。
func sentPromptTexts(sent map[string]any) []string {
	var out []string
	if s, ok := sent["instructions"].(string); ok && s != "" {
		out = append(out, s)
	}
	for _, it := range asSlice(sent["input"]) {
		item, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if role := asString(item["role"]); role == "developer" || role == "system" {
			if text := itemsText([]any{item}); text != "" {
				out = append(out, text)
			}
		}
	}
	return out
}

func sentTools(sent map[string]any) []string {
	out := []string{}
	add := func(list []any) {
		for _, t := range list {
			if id := toolIdent(t); id != "" {
				out = append(out, id)
			}
		}
	}
	add(asSlice(sent["tools"]))
	for _, it := range asSlice(sent["input"]) {
		if item, ok := it.(map[string]any); ok {
			add(asSlice(item["tools"])) // 新版 Codex 的 additional_tools 条目
		}
	}
	sort.Strings(out)
	return out
}

// isCopyOf 判断 echoed 是否只是请求里某段已有提示词的副本（允许首尾空白等细微差别）。
func isCopyOf(echoed string, sentTexts []string) bool {
	probe := strings.TrimSpace(echoed)
	if len(probe) > 1500 {
		probe = probe[:1500]
	}
	if len(probe) < 40 {
		return false
	}
	for _, text := range sentTexts {
		if strings.Contains(text, probe) {
			return true
		}
	}
	return false
}

// compareEcho 对比"发出去的请求"与"上游回显"。basisIsClient 表示拿不到 CPA 实际发往上游的请求体、
// 只能以客户端请求为基准——此时 CPA 自身的改写无法排除，级别封顶为 notice。
func compareEcho(sentDoc any, echo *requestEcho, basisIsClient bool) []echoDiff {
	sent, ok := sentDoc.(map[string]any)
	if !ok || echo == nil {
		return nil
	}
	var diffs []echoDiff
	add := func(d echoDiff) {
		if basisIsClient {
			if severityRank[d.Severity] > severityRank[sevNotice] {
				d.Severity = sevNotice
			}
			d.Note = strings.TrimSpace(d.Note + " 对比基准为客户端请求（未抓到 CPA 发往上游的请求体），不排除是 CPA 自身的改写。")
		}
		diffs = append(diffs, d)
	}

	sentIns, _ := sent["instructions"].(string)
	if echo.instructions != "" && strings.TrimSpace(echo.instructions) != strings.TrimSpace(sentIns) {
		d := echoDiff{Param: "instructions", kind: "instructions", keyPart: echo.InstructionsSHA,
			Sent:   describeText(sentIns),
			Echoed: fmt.Sprintf("%d 字符（sha %s）：%s", echo.InstructionsLen, echo.InstructionsSHA, truncate(strings.Join(strings.Fields(echo.instructions), " "), 220))}
		switch {
		case isCopyOf(echo.instructions, sentPromptTexts(sent)):
			d.Severity = sevNotice
			d.Note = "内容是请求里已有提示词的副本：模型会读到两遍，输入 token 被重复计费。"
		case sentIns != "":
			d.Severity = sevWarn
			d.Note = "请求里的 instructions 被替换成了别的文本。"
		default:
			d.Severity = sevWarn
			d.Note = fmt.Sprintf("请求里没有这段文本，是渠道注入的系统提示词：它会与客户端自带的提示词叠加甚至冲突，并按约 %d token 计入每次请求的输入。", echo.InstructionsLen/5)
		}
		add(d)
	}

	if _, declared := sent["tools"]; declared || len(sentTools(sent)) > 0 || len(echo.Tools) > 0 {
		sentSet, echoSet := sentTools(sent), echo.Tools
		added, removed := setDiff(echoSet, sentSet), setDiff(sentSet, echoSet)
		if len(added) > 0 {
			add(echoDiff{Param: "tools", kind: "tools-added", keyPart: strings.Join(added, ","), Severity: sevWarn,
				Sent: strings.Join(sentSet, ", "), Echoed: strings.Join(echoSet, ", "), Note: "渠道添加了请求里没有的工具：" + strings.Join(added, ", ")})
		}
		if len(removed) > 0 {
			add(echoDiff{Param: "tools", kind: "tools-removed", keyPart: strings.Join(removed, ","), Severity: sevNotice,
				Sent: strings.Join(sentSet, ", "), Echoed: strings.Join(echoSet, ", "), Note: "请求里声明的工具没有出现在回显中：" + strings.Join(removed, ", ")})
		}
	}

	if want, ok := sent["parallel_tool_calls"].(bool); ok && echo.ParallelToolCalls != nil && *echo.ParallelToolCalls != want {
		add(echoDiff{Param: "parallel_tool_calls", kind: "param", keyPart: "parallel_tool_calls", Severity: sevNotice, Sent: fmt.Sprint(want), Echoed: fmt.Sprint(*echo.ParallelToolCalls)})
	}
	if want := asString(nestedGet(sent, "reasoning", "effort")); want != "" && echo.ReasoningEffort != "" && echo.ReasoningEffort != want {
		add(echoDiff{Param: "reasoning.effort", kind: "param", keyPart: "reasoning.effort:" + echo.ReasoningEffort, Severity: sevWarn, Sent: want, Echoed: echo.ReasoningEffort,
			Note: "推理强度被改写，直接影响回答质量。"})
	}
	if want := asString(nestedGet(sent, "text", "verbosity")); want != "" && echo.Verbosity != "" && echo.Verbosity != want {
		add(echoDiff{Param: "text.verbosity", kind: "param", keyPart: "text.verbosity", Severity: sevNotice, Sent: want, Echoed: echo.Verbosity})
	}
	if want := asString(sent["service_tier"]); want != "" && want != "auto" && echo.ServiceTier != "" && echo.ServiceTier != want {
		add(echoDiff{Param: "service_tier", kind: "param", keyPart: "service_tier", Severity: sevNotice, Sent: want, Echoed: echo.ServiceTier})
	}
	if _, asked := sent["max_output_tokens"]; !asked && echo.MaxOutputTokens != nil {
		add(echoDiff{Param: "max_output_tokens", kind: "param", keyPart: "max_output_tokens", Severity: sevNotice, Sent: "（未设置）", Echoed: fmt.Sprint(*echo.MaxOutputTokens),
			Note: "渠道限制了输出长度。"})
	}
	return diffs
}

func describeText(s string) string {
	if s == "" {
		return "（未发送）"
	}
	return fmt.Sprintf("%d 字符：%s", len(s), truncate(strings.Join(strings.Fields(s), " "), 120))
}

// setDiff 返回在 a 中而不在 b 中的元素。
func setDiff(a, b []string) []string {
	have := make(map[string]bool, len(b))
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	return out
}

var echoTitles = map[string]string{
	"instructions":  "渠道改写了请求：注入 / 替换了系统提示词（instructions）",
	"tools-added":   "渠道改写了请求：添加了工具",
	"tools-removed": "渠道改写了请求：移除了工具",
	"param":         "渠道改写了请求参数",
}

func echoFinding(d echoDiff, base finding) finding {
	f := base
	f.Severity, f.Category, f.Rule = d.Severity, catSecurity, "request-rewritten"
	f.Title = echoTitles[d.kind]
	if d.kind == "param" {
		f.Title += "：" + d.Param
	}
	f.Detail = strings.TrimSpace("依据是上游在响应里回显的实际生效参数，与发出的请求不一致。" + d.Note)
	f.Evidence = fmt.Sprintf("%s\n  发出：%s\n  回显：%s", d.Param, d.Sent, d.Echoed)
	f.Path = d.Param
	f.Key = findingKey(f.Rule, d.kind, d.keyPart, base.Channel)
	return f
}
