package main

import (
	"bytes"
	"encoding/json"
	"hash/fnv"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // 宿主镜像缺时区数据时仍能解析 rewrite_env_timezone
)

// Codex 在 input 里放一条以 <environment_context> 开头的 user 消息，带客户端本地的
// <current_date> 与 <timezone>。配置了 rewrite_env_timezone 后，插件在 request.intercept_before
// 把这两项改写成目标时区与该时区下的日期，再交给宿主发往上游。
//
// 日期按"会话 + 原文"钉住：同一会话里某段 environment_context 第一次出现时换算一次，之后每轮都
// 复用同一结果。否则目标时区跨过零点时，历史消息的日期会跟着变，破坏前缀缓存。钉住的结果只在内存里，
// 插件重启后按重启时的时间重新换算。

const (
	dateLayout    = "2006-01-02"
	envPinTTL     = 72 * time.Hour
	envPinMax     = 20000
	envPruneEvery = 10 * time.Minute
)

var (
	envOpenTag  = []byte("<environment_context>")
	envCloseTag = "</environment_context>"
	envDateRe   = regexp.MustCompile(`<current_date>(\d{4}-\d{2}-\d{2})</current_date>`)
	envZoneRe   = regexp.MustCompile(`<timezone>([^<]*)</timezone>`)
)

type envPin struct {
	text string
	note string
	seen time.Time
}

type envRewriter struct {
	mu        sync.Mutex
	zone      string
	loc       *time.Location
	pins      map[string]*envPin
	lastPrune time.Time
	now       func() time.Time // 测试替换
}

func newEnvRewriter() *envRewriter {
	return &envRewriter{pins: make(map[string]*envPin), now: time.Now}
}

// configure 设置目标时区（parseConfig 已校验）；目标变化时清空钉住的结果。
func (r *envRewriter) configure(zone string) {
	var loc *time.Location
	if zone != "" {
		loc, _ = time.LoadLocation(zone)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if zone == r.zone {
		return
	}
	r.zone, r.loc = zone, loc
	r.pins = make(map[string]*envPin)
}

// rewrite 返回改写后的请求体与改写说明；无需改写时返回 nil。只认 input 数组里 user 消息中
// 以 <environment_context> 开头的文本块：按它在请求体里的字节区间原位替换，其余字节（包括内容
// 恰好相同的 assistant 消息、工具输出）保持不变。
func (r *envRewriter) rewrite(body []byte, headers http.Header) ([]byte, []string) {
	r.mu.Lock()
	enabled := r.loc != nil
	r.mu.Unlock()
	if !enabled || !bytes.Contains(body, envOpenTag) {
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
	var meta struct {
		PromptCacheKey string `json:"prompt_cache_key"`
	}
	_ = json.Unmarshal(body, &meta)
	session := sessionKey(headers, map[string]any{"prompt_cache_key": meta.PromptCacheKey}, nil)
	now := r.now()
	type edit struct {
		start, end int
		to         []byte
	}
	var edits []edit
	var notes []string
	for i, item := range items {
		var head struct {
			Type string `json:"type"`
			Role string `json:"role"`
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
			var text string
			if json.Unmarshal(sp.raw, &text) != nil || !strings.HasPrefix(strings.TrimSpace(text), string(envOpenTag)) {
				continue
			}
			repl, note := r.pinned(session, text, now)
			start, end := base+sp.off, base+sp.off+len(sp.raw)
			if repl == text || end > len(body) || !bytes.Equal(body[start:end], sp.raw) {
				continue
			}
			edits = append(edits, edit{start, end, jsonString(repl)})
			notes = append(notes, note)
		}
	}
	if len(edits) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, len(body)+64*len(edits))
	prev := 0
	for _, e := range edits { // 区间按出现顺序排列、互不重叠
		out = append(append(out, body[prev:e.start]...), e.to...)
		prev = e.end
	}
	return append(out, body[prev:]...), notes
}

func (r *envRewriter) pinned(session, text string, now time.Time) (string, string) {
	h := fnv.New64a()
	h.Write([]byte(text))
	key := session + "\x00" + strconv.FormatUint(h.Sum64(), 16)
	r.mu.Lock()
	defer r.mu.Unlock()
	if p := r.pins[key]; p != nil {
		p.seen = now
		return p.text, p.note
	}
	repl, note := rewriteEnvText(text, r.zone, r.loc, now)
	if now.Sub(r.lastPrune) > envPruneEvery || len(r.pins) >= envPinMax {
		r.pruneLocked(now)
	}
	r.pins[key] = &envPin{text: repl, note: note, seen: now}
	return repl, note
}

func (r *envRewriter) pruneLocked(now time.Time) {
	r.lastPrune = now
	for k, p := range r.pins {
		if now.Sub(p.seen) > envPinTTL {
			delete(r.pins, k)
		}
	}
	if len(r.pins) >= envPinMax { // 极端情况：短时间内会话过多，整体丢弃，代价只是这些会话下一轮重新换算
		r.pins = make(map[string]*envPin)
	}
}

// rewriteEnvText 改写一段 environment_context。没有 <timezone> 或已是目标时区时原样返回。
func rewriteEnvText(text, zone string, loc *time.Location, now time.Time) (string, string) {
	// 只看 environment_context 内部：同一文本块后面若还有正文，正文里的同名标签不能动
	end := strings.Index(text, envCloseTag)
	if end < 0 {
		return text, ""
	}
	block, tail := text[:end], text[end:]
	zm := envZoneRe.FindStringSubmatchIndex(block)
	if zm == nil {
		return text, ""
	}
	srcZone := block[zm[2]:zm[3]]
	if srcZone == zone {
		return text, ""
	}
	out := block[:zm[2]] + zone + block[zm[3]:]
	note := "timezone " + srcZone + " → " + zone
	if dm := envDateRe.FindStringSubmatchIndex(out); dm != nil {
		srcDate := out[dm[2]:dm[3]]
		dstDate := envTargetDate(srcDate, srcZone, loc, now)
		out = out[:dm[2]] + dstDate + out[dm[3]:]
		note += "，current_date " + srcDate + " → " + dstDate
	}
	return out + tail, note
}

// envTargetDate 估计原日期在目标时区对应哪一天。原日期就是客户端时区的"今天"时，取目标时区的当前日期；
// 更早（或更晚）的日期无法知道具体时刻，按当天正午换算。
func envTargetDate(srcDate, srcZone string, loc *time.Location, now time.Time) string {
	today := now.In(loc).Format(dateLayout)
	srcLoc, err := time.LoadLocation(srcZone)
	if err != nil || now.In(srcLoc).Format(dateLayout) == srcDate {
		return today
	}
	day, err := time.ParseInLocation(dateLayout, srcDate, srcLoc)
	if err != nil {
		return today
	}
	return day.Add(12 * time.Hour).In(loc).Format(dateLayout)
}

type textSpan struct {
	off int    // 在 content 里的偏移
	raw []byte // JSON 字符串原文（含引号）
}

// textSpans 找出消息 content 里的文本：字符串，或 [{type:"input_text"|"text", text}] 列表中的 text。
func textSpans(content []byte) []textSpan {
	if len(content) == 0 {
		return nil
	}
	if content[0] == '"' {
		return []textSpan{{0, content}}
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
			out = append(out, textSpan{starts[i] + off, raw})
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
