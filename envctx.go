package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // 宿主镜像缺时区数据时仍能解析 rewrite_env_timezone
)

const dateLayout = "2006-01-02"
const envContentKind = "environments.environment_context"

var (
	envOpenTag  = []byte("<environment_context>")
	envCloseTag = "</environment_context>"
	envDateRe   = regexp.MustCompile(`<current_date>(\d{4}-\d{2}-\d{2})</current_date>`)
	envZoneRe   = regexp.MustCompile(`<timezone>([^<]*)</timezone>`)
)

type envRewriter struct {
	// 整个请求使用同一配置快照，配置热加载不能在两个文本块之间改变时区。
	mu       sync.Mutex
	zone     string
	loc      *time.Location
	dir      string
	sessions map[string]*envSession
	now      func() time.Time
}

func newEnvRewriter() *envRewriter {
	return &envRewriter{sessions: make(map[string]*envSession), now: time.Now}
}

// 数据目录与目标时区共同隔离持久化状态；禁用再启用也不丢失历史映射。
func (r *envRewriter) configure(zone string, dirs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dir := r.dir
	if len(dirs) > 0 {
		dir = dirs[0]
	}
	if zone == r.zone && dir == r.dir {
		return
	}
	r.zone, r.dir = zone, dir
	r.loc = nil
	if zone != "" {
		r.loc, _ = time.LoadLocation(zone)
	}
	r.sessions = make(map[string]*envSession)
}

// 有类型标记时严格使用标记；发送前被清除标记的 Codex 请求使用完整环境结构兼容识别。
// 原始历史映射持久化；跨日时在 input 末尾追加当前环境更新，不回头修改历史日期。
func (r *envRewriter) rewrite(body []byte, headers http.Header, metadata ...map[string]any) ([]byte, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.loc == nil {
		return nil, nil
	}
	var doc map[string]any
	if json.Unmarshal(body, &doc) != nil {
		return nil, nil
	}
	inStart, input, ok := objectMember(body, "input")
	if !ok || len(input) == 0 || input[0] != '[' {
		return nil, nil
	}
	itemStarts, items, ok := arrayElems(input)
	if !ok {
		return nil, nil
	}
	var host map[string]any
	if len(metadata) > 0 {
		host = metadata[0]
	}
	session := envSessionKey(headers, doc, host)
	state, err := r.loadSession(session)
	if err != nil {
		logf("load environment rewrite state failed; request unchanged: %v", err)
		return nil, nil
	}
	// 克隆后再改，只有持久化成功才发布新状态，避免失败请求污染后续映射。
	next := &envSession{Version: 1, Known: state.Known, Pins: make(map[string]string, len(state.Pins))}
	for k, v := range state.Pins {
		next.Pins[k] = v
	}
	dirty := false
	now := r.now()
	today := now.In(r.loc).Format(dateLayout)
	type edit struct {
		start, end int
		to         []byte
	}
	var edits []edit
	var notes []string
	latestDate, latestZone := "", ""
	found := false
	for i, item := range items {
		var head struct {
			Type     string `json:"type"`
			Role     string `json:"role"`
			Metadata struct {
				Kinds json.RawMessage `json:"content_item_kinds"`
			} `json:"internal_chat_message_metadata_passthrough"`
		}
		if json.Unmarshal(item, &head) != nil || head.Role != "user" || (head.Type != "" && head.Type != "message") {
			continue
		}
		cStart, content, ok := objectMember(item, "content")
		if !ok {
			continue
		}
		base := inStart + itemStarts[i] + cStart
		for _, sp := range textSpans(content) {
			var kinds []string
			marked := len(head.Metadata.Kinds) > 0 && string(head.Metadata.Kinds) != "null"
			if marked && (json.Unmarshal(head.Metadata.Kinds, &kinds) != nil || sp.index >= len(kinds) || kinds[sp.index] != envContentKind) {
				continue
			}
			var text string
			if json.Unmarshal(sp.raw, &text) != nil || !strings.HasPrefix(strings.TrimSpace(text), string(envOpenTag)) {
				continue
			}
			if !marked && !legacyEnvContext(text, headers, doc, state.Known) {
				continue
			}
			date, zone, valid := envValues(text)
			if !valid || zone == "" {
				continue
			}
			found = true
			repl, note := text, ""
			// 没有稳定会话 ID 时不钉住也不改历史，只追加无状态的当前环境更新。
			if session != "" {
				key := envHash(text)
				mapped, exists := next.Pins[key]
				if !exists {
					mapped = ""
					if zone != r.zone {
						if date == "" {
							mapped = "-"
						} else {
							mapped = envTargetDate(date, zone, r.loc, now)
						}
					}
					next.Pins[key] = mapped
					dirty = true
				}
				if mapped != "" {
					repl, note = replaceEnvValues(text, r.zone, mapped)
				}
			}
			latestDate, latestZone, _ = envValues(repl)
			start, end := base+sp.off, base+sp.off+len(sp.raw)
			if repl == text || end > len(body) || !bytes.Equal(body[start:end], sp.raw) {
				continue
			}
			edits = append(edits, edit{start, end, jsonString(repl)})
			notes = append(notes, note)
		}
	}
	if found && !next.Known {
		next.Known = true
		dirty = true
	}
	// continuation / 压缩后可能只带工具结果：已识别的会话仍补充当前日期。
	// 不以“上次发过”省略更新，因为上次请求可能失败，且服务端历史不一定包含该更新。
	if next.Known && (latestDate != today || latestZone != r.zone) {
		update := []byte(`{"type":"message","role":"user","content":[{"type":"input_text","text":`)
		update = append(update, jsonString("<environment_context>\n  <current_date>"+today+"</current_date>\n  <timezone>"+r.zone+"</timezone>\n</environment_context>")...)
		update = append(update, []byte(`}],"internal_chat_message_metadata_passthrough":{"content_item_kinds":["environments.environment_context"]}}`)...)
		if len(items) > 0 {
			update = append([]byte{','}, update...)
		}
		at := inStart + len(input) - 1
		edits = append(edits, edit{at, at, update})
		notes = append(notes, "追加当前环境：current_date "+today+"，timezone "+r.zone)
	}
	if dirty && session != "" {
		if err := r.saveSession(session, next); err != nil {
			logf("persist environment rewrite state failed; request unchanged: %v", err)
			return nil, nil
		}
	}
	if len(edits) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, len(body)+512)
	prev := 0
	for _, e := range edits {
		out = append(append(out, body[prev:e.start]...), e.to...)
		prev = e.end
	}
	return append(out, body[prev:]...), notes
}

func envValues(text string) (date, zone string, valid bool) {
	end := strings.Index(text, envCloseTag)
	if end < 0 {
		return "", "", false
	}
	block := text[:end]
	if m := envDateRe.FindStringSubmatch(block); m != nil {
		date = m[1]
	}
	if m := envZoneRe.FindStringSubmatch(block); m != nil {
		zone = m[1]
	}
	return date, zone, true
}

func replaceEnvValues(text, zone, date string) (string, string) {
	end := strings.Index(text, envCloseTag)
	if end < 0 {
		return text, ""
	}
	block, tail := text[:end], text[end:]
	zm := envZoneRe.FindStringSubmatchIndex(block)
	if zm == nil {
		return text, ""
	}
	note := "timezone " + block[zm[2]:zm[3]] + " → " + zone
	out := block[:zm[2]] + zone + block[zm[3]:]
	if date != "-" {
		if dm := envDateRe.FindStringSubmatchIndex(out); dm != nil {
			note += "，current_date " + out[dm[2]:dm[3]] + " → " + date
			out = out[:dm[2]] + date + out[dm[3]:]
		}
	}
	return out + tail, note
}

// 只有首次观察到的源时区“今天”可按当前时刻映射；历史日期没有时分秒，不能按正午猜测。
// 返回空值表示保留历史原文，由请求末尾的当前环境更新提供目标时区与今天。
func envTargetDate(srcDate, srcZone string, loc *time.Location, now time.Time) string {
	srcLoc, err := time.LoadLocation(srcZone)
	if err != nil || srcZone == "Local" || loc == nil || now.In(srcLoc).Format(dateLayout) != srcDate {
		return ""
	}
	return now.In(loc).Format(dateLayout)
}

type textSpan struct {
	index int    // 原 content 数组索引，不能使用过滤后的文本索引
	off   int    // 在 content 里的偏移
	raw   []byte // JSON 字符串原文（含引号）
}

// textSpans 找出消息 content 里的文本：字符串，或 [{type:"input_text"|"text", text}] 列表中的 text。
func textSpans(content []byte) []textSpan {
	if len(content) == 0 {
		return nil
	}
	if content[0] == '"' {
		return []textSpan{{index: 0, off: 0, raw: content}}
	}
	starts, parts, ok := arrayElems(content)
	if !ok {
		return nil
	}
	var out []textSpan
	for i, part := range parts {
		var p struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(part, &p) != nil || (p.Type != "input_text" && p.Type != "text") {
			continue
		}
		if off, raw, ok := objectMember(part, "text"); ok && len(raw) > 0 && raw[0] == '"' {
			out = append(out, textSpan{index: i, off: starts[i] + off, raw: raw})
		}
	}
	return out
}

// objectMember 返回 JSON 对象 raw 中第一个键为 key 的值，以及该值在 raw 中的起始偏移。
func objectMember(raw []byte, key string) (int, []byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return 0, nil, false
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return 0, nil, false
		}
		off := valueStart(raw, int(dec.InputOffset()))
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return 0, nil, false
		}
		if !spanMatches(raw, off, v) {
			return 0, nil, false
		}
		if k, _ := t.(string); k == key {
			return off, raw[off : off+len(v)], true
		}
	}
	return 0, nil, false
}

// arrayElems 返回 JSON 数组 raw 的各元素及其在 raw 中的起始偏移。
func arrayElems(raw []byte) ([]int, [][]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return nil, nil, false
	}
	var starts []int
	var elems [][]byte
	for dec.More() {
		off := valueStart(raw, int(dec.InputOffset()))
		var v json.RawMessage
		if dec.Decode(&v) != nil {
			return nil, nil, false
		}
		if !spanMatches(raw, off, v) {
			return nil, nil, false
		}
		starts, elems = append(starts, off), append(elems, raw[off:off+len(v)])
	}
	return starts, elems, true
}

// spanMatches 确认解码器给出的值确实位于 raw[off:]，偏移算错时宁可放弃改写也不越界。
func spanMatches(raw []byte, off int, v []byte) bool {
	return off+len(v) <= len(raw) && bytes.Equal(raw[off:off+len(v)], v)
}

// valueStart 跳过 off 处的空白与分隔符（冒号、逗号），返回下一个 JSON 值的起点。
func valueStart(raw []byte, off int) int {
	for off < len(raw) && strings.IndexByte(" \t\r\n:,", raw[off]) >= 0 {
		off++
	}
	return off
}

// jsonString 按 serde_json 的习惯编码（不转义 <>&），尽量与 Codex 发出的字节风格一致。
func jsonString(s string) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// 无标记请求只能启发式识别：必须来自 Codex，并且文本完整地由环境 XML 构成。
// 不接受尾随说明、代码围栏或仅有日期/时区的孤立示例。已识别会话允许官方日期增量。
func legacyEnvContext(text string, headers http.Header, doc map[string]any, known bool) bool {
	client, _ := doc["client_metadata"].(map[string]any)
	codex := false
	for key, values := range headers {
		if strings.EqualFold(key, "User-Agent") || strings.EqualFold(key, "Originator") {
			for _, value := range values {
				if strings.HasPrefix(strings.ToLower(value), "codex") {
					codex = true
				}
			}
		}
	}
	if asString(client["session_id"]) != "" && asString(client["thread_id"]) != "" {
		for key := range client {
			if strings.HasPrefix(key, "x-codex-") {
				codex = true
			}
		}
	}
	if !codex {
		return false
	}
	decoder := xml.NewDecoder(strings.NewReader(strings.TrimSpace(text)))
	depth, roots := 0, 0
	fields := make(map[string]string)
	current := ""
	allowed := map[string]bool{"cwd": true, "shell": true, "shell_version": true, "current_date": true, "timezone": true, "filesystem": true, "network": true, "environments": true, "subagents": true}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		switch v := token.(type) {
		case xml.StartElement:
			if v.Name.Space != "" {
				return false
			}
			if depth == 0 {
				roots++
				if roots != 1 || v.Name.Local != "environment_context" || len(v.Attr) != 0 {
					return false
				}
			}
			if depth == 1 {
				if !allowed[v.Name.Local] {
					return false
				}
				if _, duplicate := fields[v.Name.Local]; duplicate {
					return false
				}
				current = v.Name.Local
				fields[current] = ""
			}
			if depth >= 2 && (current == "current_date" || current == "timezone" || current == "cwd" || current == "shell") {
				return false
			}
			depth++
		case xml.EndElement:
			depth--
			if depth == 1 {
				current = ""
			}
		case xml.CharData:
			if depth <= 1 && strings.TrimSpace(string(v)) != "" {
				return false
			}
			if depth == 2 {
				fields[current] += string(v)
			}
		default:
			return false
		}
	}
	if roots != 1 || depth != 0 {
		return false
	}
	if _, err := time.Parse(dateLayout, fields["current_date"]); err != nil {
		return false
	}
	if fields["timezone"] == "Local" {
		return false
	}
	if _, err := time.LoadLocation(fields["timezone"]); err != nil || fields["timezone"] == "" {
		return false
	}
	if strings.TrimSpace(fields["cwd"]) != "" && strings.TrimSpace(fields["shell"]) != "" {
		return true
	}
	return known && len(fields) == 2
}
