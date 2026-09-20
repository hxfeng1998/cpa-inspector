package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// 流重组：把上游/下游的 SSE 分片还原成一条可读的消息（内容块、工具调用、usage、结束原因），
// 同时做协议完整性检查。协议按载荷特征自动识别，不信任宿主给的格式名。

const (
	fmtClaude    = "claude"
	fmtChat      = "openai-chat"
	fmtResponses = "openai-responses"
	fmtGemini    = "gemini"
	fmtUnknown   = "unknown"

	blockTextCap = 256 << 10
)

// sseEvent 是从一个分片里解析出的单个事件。
type sseEvent struct {
	Name string // SSE event: 行，或载荷内的 type
	Data []byte // data: 载荷原文
	JSON any    // 解析成功时的 JSON 值
	Done bool   // [DONE] 哨兵
}

// sseParser 容忍各种分片形态：整段 "event:..\ndata:..\n\n"、单独一行、无前缀的裸 JSON。
// event: 行可能与 data: 行落在不同分片里，所以事件名跨调用保留。
type sseParser struct {
	pendingEvent string
}

func (p *sseParser) parse(chunk []byte) []sseEvent {
	var out []sseEvent
	for _, line := range bytes.Split(chunk, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		switch {
		case bytes.HasPrefix(trimmed, []byte("event:")):
			p.pendingEvent = string(bytes.TrimSpace(trimmed[len("event:"):]))
			continue
		case bytes.HasPrefix(trimmed, []byte("data:")):
			trimmed = bytes.TrimSpace(trimmed[len("data:"):])
		case trimmed[0] == ':' || bytes.HasPrefix(trimmed, []byte("id:")) || bytes.HasPrefix(trimmed, []byte("retry:")):
			continue
		}
		if len(trimmed) == 0 {
			continue
		}
		ev := sseEvent{Name: p.pendingEvent, Data: append([]byte(nil), trimmed...)}
		p.pendingEvent = ""
		if bytes.Equal(trimmed, []byte("[DONE]")) {
			ev.Done = true
			ev.Name = "[DONE]"
		} else if v, ok := decodeJSON(trimmed); ok {
			ev.JSON = v
			if obj, isObj := v.(map[string]any); isObj {
				if t, _ := obj["type"].(string); t != "" && ev.Name == "" {
					ev.Name = t
				}
			}
		}
		out = append(out, ev)
	}
	return out
}

// ---------- 重组后的消息 ----------

type block struct {
	Type         string `json:"type"`
	Text         string `json:"text,omitempty"`
	Name         string `json:"name,omitempty"`
	ID           string `json:"id,omitempty"`
	Input        string `json:"input,omitempty"`
	SignatureLen int    `json:"signature_len,omitempty"`
	Truncated    bool   `json:"truncated,omitempty"`
	open         bool
}

type message struct {
	Format      string         `json:"format"`
	ID          string         `json:"id,omitempty"`
	Model       string         `json:"model,omitempty"`
	Role        string         `json:"role,omitempty"`
	StopReason  string         `json:"stop_reason,omitempty"`
	Blocks      []*block       `json:"blocks"`
	Usage       map[string]any `json:"usage,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
	EventCounts map[string]int `json:"event_counts,omitempty"`
	Done        bool           `json:"done"`
	Error       string         `json:"error,omitempty"`
	Issues      []string       `json:"issues,omitempty"`

	claudeBlocks map[int]*block // content_block index → block
	chatTools    map[string]*block
	respItems    map[string]*block
	sawStart     bool
}

func newMessage() *message {
	return &message{Format: fmtUnknown, EventCounts: make(map[string]int)}
}

func (b *block) appendText(s string) {
	if len(b.Text)+len(s) > blockTextCap {
		b.Truncated = true
		return
	}
	b.Text += s
}

func (b *block) appendInput(s string) {
	if len(b.Input)+len(s) > blockTextCap {
		b.Truncated = true
		return
	}
	b.Input += s
}

func (m *message) setExtra(key string, v any) {
	if v == nil {
		return
	}
	if m.Extra == nil {
		m.Extra = make(map[string]any)
	}
	m.Extra[key] = v
}

func (m *message) mergeUsage(v any) {
	obj, ok := v.(map[string]any)
	if !ok {
		return
	}
	if m.Usage == nil {
		m.Usage = make(map[string]any)
	}
	for k, val := range obj {
		m.Usage[k] = val
	}
}

func detectFormat(obj map[string]any) string {
	if t, _ := obj["type"].(string); t != "" {
		switch {
		case strings.HasPrefix(t, "response."):
			return fmtResponses
		case t == "message" || t == "ping" || t == "error" || strings.HasPrefix(t, "message_") || strings.HasPrefix(t, "content_block_"):
			return fmtClaude
		}
	}
	if _, ok := obj["choices"]; ok {
		return fmtChat
	}
	if o, _ := obj["object"].(string); o == "response" {
		return fmtResponses
	}
	if _, ok := obj["output"]; ok {
		if _, isArr := obj["output"].([]any); isArr {
			return fmtResponses
		}
	}
	if _, ok := obj["candidates"]; ok {
		return fmtGemini
	}
	if _, ok := obj["usageMetadata"]; ok {
		return fmtGemini
	}
	if inner, ok := obj["response"].(map[string]any); ok { // Gemini CLI / Antigravity 的外层包装
		if _, has := inner["candidates"]; has {
			return fmtGemini
		}
	}
	return fmtUnknown
}

// feed 吸收一个流事件。
func (m *message) feed(ev sseEvent) {
	name := ev.Name
	if name == "" {
		name = "(data)"
	}
	m.EventCounts[name]++
	if ev.Done {
		m.Done = true
		return
	}
	obj, ok := ev.JSON.(map[string]any)
	if !ok {
		return
	}
	format := detectFormat(obj)
	if m.Format == fmtUnknown {
		m.Format = format
	}
	switch format {
	case fmtClaude:
		m.feedClaude(obj)
	case fmtChat:
		m.feedChat(obj)
	case fmtResponses:
		m.feedResponses(obj)
	case fmtGemini:
		m.feedGemini(obj)
	}
}

// feedDocument 吸收一份非流式完整响应。
func (m *message) feedDocument(v any) {
	obj, ok := v.(map[string]any)
	if !ok {
		return
	}
	m.Format = detectFormat(obj)
	switch m.Format {
	case fmtClaude:
		if t, _ := obj["type"].(string); t == "error" {
			m.feedClaude(obj)
			return
		}
		m.claudeHeader(obj)
		m.StopReason, _ = obj["stop_reason"].(string)
		for _, item := range asSlice(obj["content"]) {
			if cb, ok := item.(map[string]any); ok {
				m.Blocks = append(m.Blocks, claudeBlock(cb))
			}
		}
		m.Done = true
	case fmtChat:
		m.feedChat(obj)
		m.Done = true
	case fmtResponses:
		m.absorbResponseObject(obj)
		m.Done = true
	case fmtGemini:
		m.feedGemini(obj)
		m.Done = m.StopReason != ""
	}
}

func (m *message) claudeHeader(msg map[string]any) {
	m.ID, _ = msg["id"].(string)
	m.Model, _ = msg["model"].(string)
	m.Role, _ = msg["role"].(string)
	m.mergeUsage(msg["usage"])
	m.setExtra("service_tier", nestedGet(msg, "usage", "service_tier"))
	m.setExtra("container", msg["container"])
}

func claudeBlock(cb map[string]any) *block {
	b := &block{}
	b.Type, _ = cb["type"].(string)
	b.ID, _ = cb["id"].(string)
	b.Name, _ = cb["name"].(string)
	if s, ok := cb["text"].(string); ok {
		b.appendText(s)
	}
	if s, ok := cb["thinking"].(string); ok {
		b.appendText(s)
	}
	if s, ok := cb["data"].(string); ok && b.Type == "redacted_thinking" {
		b.SignatureLen = len(s)
	}
	if s, ok := cb["signature"].(string); ok {
		b.SignatureLen = len(s)
	}
	if input, ok := cb["input"]; ok && input != nil {
		if raw, err := json.Marshal(input); err == nil && string(raw) != "{}" {
			b.appendInput(string(raw))
		}
	}
	if b.Type != "text" && b.Type != "thinking" && b.Type != "tool_use" && b.Type != "server_tool_use" && b.Type != "redacted_thinking" {
		if raw, err := json.Marshal(cb); err == nil { // 未知/少见块类型：保留原文便于查看
			b.appendInput(string(raw))
		}
	}
	return b
}

func (m *message) feedClaude(obj map[string]any) {
	t, _ := obj["type"].(string)
	switch t {
	case "message_start":
		if m.sawStart {
			m.Issues = append(m.Issues, "重复的 message_start")
		}
		m.sawStart = true
		if msg, ok := obj["message"].(map[string]any); ok {
			m.claudeHeader(msg)
		}
	case "content_block_start":
		idx := asInt(obj["index"])
		if m.claudeBlocks == nil {
			m.claudeBlocks = make(map[int]*block)
		}
		if prev := m.claudeBlocks[idx]; prev != nil && prev.open {
			m.Issues = append(m.Issues, fmt.Sprintf("内容块 #%d 未关闭就再次开始", idx))
		}
		cb, _ := obj["content_block"].(map[string]any)
		b := claudeBlock(cb)
		b.open = true
		m.claudeBlocks[idx] = b
		m.Blocks = append(m.Blocks, b)
	case "content_block_delta":
		idx := asInt(obj["index"])
		b := m.claudeBlocks[idx]
		if b == nil {
			m.Issues = append(m.Issues, fmt.Sprintf("内容块 #%d 在 start 之前收到 delta", idx))
			if m.claudeBlocks == nil {
				m.claudeBlocks = make(map[int]*block)
			}
			b = &block{Type: "unknown", open: true}
			m.claudeBlocks[idx] = b
			m.Blocks = append(m.Blocks, b)
		}
		delta, _ := obj["delta"].(map[string]any)
		switch dt, _ := delta["type"].(string); dt {
		case "text_delta":
			b.appendText(asString(delta["text"]))
		case "thinking_delta":
			b.appendText(asString(delta["thinking"]))
		case "input_json_delta":
			b.appendInput(asString(delta["partial_json"]))
		case "signature_delta":
			b.SignatureLen += len(asString(delta["signature"]))
		}
	case "content_block_stop":
		if b := m.claudeBlocks[asInt(obj["index"])]; b != nil {
			b.open = false
		}
	case "message_delta":
		if delta, ok := obj["delta"].(map[string]any); ok {
			if s, ok := delta["stop_reason"].(string); ok {
				m.StopReason = s
			}
			m.setExtra("container", delta["container"])
		}
		m.mergeUsage(obj["usage"])
		m.setExtra("context_management", obj["context_management"])
	case "message_stop":
		m.Done = true
	case "error":
		if e, ok := obj["error"].(map[string]any); ok {
			m.Error = strings.TrimSpace(asString(e["type"]) + ": " + asString(e["message"]))
		}
	}
}

func (m *message) feedChat(obj map[string]any) {
	if s, ok := obj["id"].(string); ok && s != "" {
		m.ID = s
	}
	if s, ok := obj["model"].(string); ok && s != "" {
		m.Model = s
	}
	m.setExtra("system_fingerprint", obj["system_fingerprint"])
	m.setExtra("service_tier", obj["service_tier"])
	m.setExtra("provider", obj["provider"])
	if obj["usage"] != nil {
		m.mergeUsage(obj["usage"])
	}
	if e, ok := obj["error"].(map[string]any); ok {
		m.Error = asString(e["message"])
	}
	for _, c := range asSlice(obj["choices"]) {
		choice, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := choice["finish_reason"].(string); ok && s != "" {
			m.StopReason = s
		}
		part, _ := choice["delta"].(map[string]any)
		if part == nil {
			part, _ = choice["message"].(map[string]any)
		}
		if part == nil {
			continue
		}
		if s, ok := part["role"].(string); ok && s != "" {
			m.Role = s
		}
		for _, key := range []string{"reasoning_content", "reasoning"} {
			if s, ok := part[key].(string); ok && s != "" {
				m.tailBlock("thinking").appendText(s)
			}
		}
		if s, ok := part["content"].(string); ok && s != "" {
			m.tailBlock("text").appendText(s)
		}
		if s, ok := part["refusal"].(string); ok && s != "" {
			m.tailBlock("refusal").appendText(s)
		}
		for _, tc := range asSlice(part["tool_calls"]) {
			call, ok := tc.(map[string]any)
			if !ok {
				continue
			}
			key := fmt.Sprintf("%d/%d", asInt(choice["index"]), asInt(call["index"]))
			if m.chatTools == nil {
				m.chatTools = make(map[string]*block)
			}
			b := m.chatTools[key]
			if b == nil {
				b = &block{Type: "tool_use"}
				m.chatTools[key] = b
				m.Blocks = append(m.Blocks, b)
			}
			if s, ok := call["id"].(string); ok && s != "" {
				b.ID = s
			}
			if fn, ok := call["function"].(map[string]any); ok {
				if s, ok := fn["name"].(string); ok && s != "" {
					b.Name += s
				}
				b.appendInput(asString(fn["arguments"]))
			}
		}
	}
}

// tailBlock 返回末尾同类型块，没有则新建（chat 增量文本没有块边界）。
func (m *message) tailBlock(typ string) *block {
	if n := len(m.Blocks); n > 0 && m.Blocks[n-1].Type == typ {
		return m.Blocks[n-1]
	}
	b := &block{Type: typ}
	m.Blocks = append(m.Blocks, b)
	return b
}

func (m *message) feedResponses(obj map[string]any) {
	t, _ := obj["type"].(string)
	switch t {
	case "response.created", "response.in_progress":
		if resp, ok := obj["response"].(map[string]any); ok {
			m.ID, _ = resp["id"].(string)
			m.Model, _ = resp["model"].(string)
		}
	case "response.output_text.delta":
		m.respItem(obj, "text").appendText(asString(obj["delta"]))
	case "response.reasoning_summary_text.delta", "response.reasoning_text.delta":
		m.respItem(obj, "thinking").appendText(asString(obj["delta"]))
	case "response.refusal.delta":
		m.respItem(obj, "refusal").appendText(asString(obj["delta"]))
	case "response.function_call_arguments.delta", "response.custom_tool_call_input.delta":
		m.respItem(obj, "tool_use").appendInput(asString(obj["delta"]))
	case "response.output_item.added", "response.output_item.done":
		item, _ := obj["item"].(map[string]any)
		itemType, _ := item["type"].(string)
		if itemType == "function_call" || itemType == "custom_tool_call" || itemType == "local_shell_call" {
			b := m.respItem(map[string]any{"item_id": item["id"]}, "tool_use")
			if s, ok := item["name"].(string); ok && s != "" {
				b.Name = s
			}
			if s, ok := item["call_id"].(string); ok && s != "" {
				b.ID = s
			}
			if t == "response.output_item.done" {
				if s := asString(item["arguments"]) + asString(item["input"]); s != "" {
					b.Input = truncate(s, blockTextCap)
				}
			}
		}
	case "response.completed", "response.incomplete", "response.failed":
		if resp, ok := obj["response"].(map[string]any); ok {
			m.absorbResponseObject(resp)
		}
		m.Done = true
	case "error":
		m.Error = asString(obj["message"])
	}
}

func (m *message) respItem(obj map[string]any, typ string) *block {
	key := asString(obj["item_id"]) + "/" + typ + "/" + fmt.Sprint(asInt(obj["content_index"])+asInt(obj["summary_index"]))
	if m.respItems == nil {
		m.respItems = make(map[string]*block)
	}
	b := m.respItems[key]
	if b == nil {
		b = &block{Type: typ}
		m.respItems[key] = b
		m.Blocks = append(m.Blocks, b)
	}
	return b
}

// absorbResponseObject 以终态 response 对象为准重建内容（比增量拼接可靠）。
func (m *message) absorbResponseObject(resp map[string]any) {
	if s, ok := resp["id"].(string); ok && s != "" {
		m.ID = s
	}
	if s, ok := resp["model"].(string); ok && s != "" {
		m.Model = s
	}
	m.StopReason, _ = resp["status"].(string)
	if reason := nestedGet(resp, "incomplete_details", "reason"); reason != nil {
		m.StopReason += ":" + asString(reason)
	}
	if e, ok := resp["error"].(map[string]any); ok {
		m.Error = strings.TrimSpace(asString(e["code"]) + ": " + asString(e["message"]))
	}
	m.mergeUsage(resp["usage"])
	m.setExtra("service_tier", resp["service_tier"])
	output := asSlice(resp["output"])
	if len(output) == 0 {
		return
	}
	m.Blocks = m.Blocks[:0]
	for _, it := range output {
		item, ok := it.(map[string]any)
		if !ok {
			continue
		}
		switch itemType, _ := item["type"].(string); itemType {
		case "message":
			for _, c := range asSlice(item["content"]) {
				part, _ := c.(map[string]any)
				typ := "text"
				if pt, _ := part["type"].(string); pt == "refusal" {
					typ = "refusal"
				}
				b := &block{Type: typ}
				b.appendText(asString(part["text"]) + asString(part["refusal"]))
				m.Blocks = append(m.Blocks, b)
			}
		case "reasoning":
			b := &block{Type: "thinking", SignatureLen: len(asString(item["encrypted_content"]))}
			for _, s := range asSlice(item["summary"]) {
				if part, ok := s.(map[string]any); ok {
					b.appendText(asString(part["text"]))
				}
			}
			m.Blocks = append(m.Blocks, b)
		case "function_call", "custom_tool_call", "local_shell_call":
			b := &block{Type: "tool_use", Name: asString(item["name"]), ID: asString(item["call_id"])}
			b.appendInput(asString(item["arguments"]) + asString(item["input"]))
			if itemType == "local_shell_call" {
				b.Name = "local_shell"
				if raw, err := json.Marshal(item["action"]); err == nil {
					b.appendInput(string(raw))
				}
			}
			m.Blocks = append(m.Blocks, b)
		default:
			b := &block{Type: itemType}
			if raw, err := json.Marshal(item); err == nil {
				b.appendInput(string(raw))
			}
			m.Blocks = append(m.Blocks, b)
		}
	}
}

func (m *message) feedGemini(obj map[string]any) {
	if inner, ok := obj["response"].(map[string]any); ok {
		obj = inner
	}
	if s, ok := obj["responseId"].(string); ok && s != "" {
		m.ID = s
	}
	if s, ok := obj["modelVersion"].(string); ok && s != "" {
		m.Model = s
	}
	if obj["usageMetadata"] != nil {
		m.mergeUsage(obj["usageMetadata"])
	}
	if pf, ok := obj["promptFeedback"].(map[string]any); ok {
		m.setExtra("promptFeedback", pf)
	}
	for _, c := range asSlice(obj["candidates"]) {
		cand, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if s, ok := cand["finishReason"].(string); ok && s != "" {
			m.StopReason = s
			m.Done = true
		}
		content, _ := cand["content"].(map[string]any)
		if s, ok := content["role"].(string); ok {
			m.Role = s
		}
		for _, p := range asSlice(content["parts"]) {
			part, ok := p.(map[string]any)
			if !ok {
				continue
			}
			sigLen := len(asString(part["thoughtSignature"]))
			if fc, ok := part["functionCall"].(map[string]any); ok {
				b := &block{Type: "tool_use", Name: asString(fc["name"]), ID: asString(fc["id"]), SignatureLen: sigLen}
				if raw, err := json.Marshal(fc["args"]); err == nil {
					b.appendInput(string(raw))
				}
				m.Blocks = append(m.Blocks, b)
				continue
			}
			if s, ok := part["text"].(string); ok {
				typ := "text"
				if thought, _ := part["thought"].(bool); thought {
					typ = "thinking"
				}
				b := m.tailBlock(typ)
				b.appendText(s)
				b.SignatureLen += sigLen
				continue
			}
			b := &block{Type: "part"}
			if raw, err := json.Marshal(part); err == nil {
				b.appendInput(truncate(string(raw), 4096))
			}
			m.Blocks = append(m.Blocks, b)
		}
	}
}

// finish 在请求结束时做协议完整性检查。succeeded 为 false（失败/取消）时不检查截断。
// upstream 标明方向：个别结束哨兵只在上游一侧可见。
func (m *message) finish(stream, succeeded, upstream bool) {
	if !succeeded || m.Error != "" {
		return
	}
	switch m.Format {
	case fmtClaude:
		if stream {
			if !m.sawStart {
				m.Issues = append(m.Issues, "流中缺少 message_start")
			}
			if !m.Done {
				m.Issues = append(m.Issues, "流未以 message_stop 结束（可能被截断）")
			}
			for idx, b := range m.claudeBlocks {
				if b.open {
					m.Issues = append(m.Issues, fmt.Sprintf("内容块 #%d 缺少 content_block_stop", idx))
				}
			}
		}
		if m.StopReason == "" {
			m.Issues = append(m.Issues, "缺少 stop_reason")
		}
	case fmtChat:
		if m.StopReason == "" {
			m.Issues = append(m.Issues, "缺少 finish_reason")
		}
		if stream && !m.Done && upstream { // 下游的 [DONE] 由宿主在拦截点之后补写，看不到属正常
			m.Issues = append(m.Issues, "流未以 [DONE] 结束")
		}
	case fmtResponses:
		if stream && !m.Done {
			m.Issues = append(m.Issues, "流未收到 response.completed")
		}
	}
	sort.Strings(m.Issues)
}

// toolCalls 返回消息里的工具调用块。
func (m *message) toolCalls() []*block {
	var out []*block
	for _, b := range m.Blocks {
		if b.Type == "tool_use" || b.Type == "server_tool_use" {
			out = append(out, b)
		}
	}
	return out
}

// inputTokens 返回上游计费口径的输入 token 总数（含缓存读写），未知返回 -1。
func (m *message) inputTokens() int64 {
	if m.Usage == nil {
		return -1
	}
	switch m.Format {
	case fmtClaude:
		return asInt64(m.Usage["input_tokens"]) + asInt64(m.Usage["cache_read_input_tokens"]) + asInt64(m.Usage["cache_creation_input_tokens"])
	case fmtChat:
		return asInt64(m.Usage["prompt_tokens"])
	case fmtResponses:
		return asInt64(m.Usage["input_tokens"])
	case fmtGemini:
		return asInt64(m.Usage["promptTokenCount"])
	}
	return -1
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

func asInt(v any) int { return int(asInt64(v)) }

func asInt64(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
		f, _ := n.Float64()
		return int64(f)
	case float64:
		return int64(n)
	}
	return 0
}

func nestedGet(obj map[string]any, keys ...string) any {
	var cur any = obj
	for _, k := range keys {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}
