package main

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"
)

// 缓存失效检测。
//
// 提示词缓存的命中条件是"同一账号（组织）下、前缀逐字节相同、且未过期"。第三方渠道背后往往是账号池：
// 会话中途被切到另一个账号、或渠道换了一份注入的 instructions，前缀缓存就全部作废——
// OpenAI 侧按原价重新计费，Claude 侧还要再付一次缓存写入的溢价。
//
// 判定很保守，只在"本该命中"时才报：同一会话里存在一个已结束的上一轮，本轮请求与它共享 ≥90% 的前缀，
// 间隔在 TTL 内，上一轮输入足够长——而本轮的缓存读还不到预期的一半。

const (
	cacheTTL            = 5 * time.Minute // Claude 默认 TTL；OpenAI 为 5–10 分钟起。取最短的，宁可漏报
	cacheMinPrevTokens  = 2048
	cacheMinSharedRatio = 0.90
	cacheHitFloor       = 0.50 // 缓存读 < 预期 × 该比例 视为失效
	sessionKeepTurns    = 8
	sessionMaxAge       = 2 * time.Hour
	sessionMaxCount     = 500
)

type sessionTurn struct {
	reqID     string
	started   time.Time
	completed time.Time
	model     string
	channel   string
	authID    string
	insSHA    string // 渠道回显的 instructions 指纹（"" 表示无回显，"none" 表示回显为空）
	items     []uint64
	sizes     []int
	total     int64 // 输入 token 总量（含缓存部分）
	cached    int64
}

type sessionTracker struct {
	mu       sync.Mutex
	sessions map[string][]sessionTurn
	lastSeen map[string]time.Time
}

func newSessionTracker() *sessionTracker {
	return &sessionTracker{sessions: make(map[string][]sessionTurn), lastSeen: make(map[string]time.Time)}
}

type cacheVerdict struct {
	Expected int64  `json:"expected_cached_tokens"`
	Actual   int64  `json:"actual_cached_tokens"`
	Lost     int64  `json:"lost_tokens"`
	GapSec   int64  `json:"gap_seconds"`
	Shared   int    `json:"shared_prefix_percent"`
	PrevID   string `json:"previous_request_id"`
	Cause    string `json:"cause"`
	causeKey string
}

// observe 记录本轮，并在"本该命中却没命中"时返回判定。
func (t *sessionTracker) observe(session string, cur sessionTurn) *cacheVerdict {
	if session == "" || len(cur.items) == 0 || cur.total <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	turns := t.sessions[session]
	var verdict *cacheVerdict
	if prev, sharedBytes, prevBytes := bestPredecessor(turns, cur); prev != nil {
		ratio := float64(sharedBytes) / float64(prevBytes)
		gap := cur.started.Sub(prev.started)
		expected := int64(float64(prev.total) * ratio)
		if ratio >= cacheMinSharedRatio && gap <= cacheTTL && prev.total >= cacheMinPrevTokens && float64(cur.cached) < cacheHitFloor*float64(expected) {
			cause, key := cacheLossCause(prev, &cur)
			verdict = &cacheVerdict{Expected: expected, Actual: cur.cached, Lost: expected - cur.cached, GapSec: int64(gap.Seconds()),
				Shared: int(ratio * 100), PrevID: prev.reqID, Cause: cause, causeKey: key}
		}
	}
	turns = append(turns, cur)
	if len(turns) > sessionKeepTurns {
		turns = turns[len(turns)-sessionKeepTurns:]
	}
	t.sessions[session], t.lastSeen[session] = turns, cur.started
	t.pruneLocked(cur.started)
	return verdict
}

// bestPredecessor 在同模型、且在本轮开始前已结束的历史轮次里，找与本轮公共前缀最长的那一轮。
// （Codex 会在同一会话里并行发"生成标题"之类的旁路请求，所以不能简单取上一条。）
func bestPredecessor(turns []sessionTurn, cur sessionTurn) (best *sessionTurn, sharedBytes, prevBytes int) {
	for i := range turns {
		p := &turns[i]
		if p.model != cur.model || p.completed.After(cur.started) || p.reqID == cur.reqID {
			continue
		}
		shared, total := 0, 0
		for _, size := range p.sizes {
			total += size
		}
		for j := 0; j < len(p.items) && j < len(cur.items) && p.items[j] == cur.items[j]; j++ {
			shared += p.sizes[j]
		}
		if total > 0 && (best == nil || shared > sharedBytes) {
			best, sharedBytes, prevBytes = p, shared, total
		}
	}
	return best, sharedBytes, prevBytes
}

func cacheLossCause(prev, cur *sessionTurn) (string, string) {
	var causes, keys []string
	if prev.channel != cur.channel && prev.channel != "" && cur.channel != "" {
		causes, keys = append(causes, fmt.Sprintf("渠道变了（%s → %s）", prev.channel, cur.channel)), append(keys, "channel")
	}
	if prev.authID != cur.authID && prev.authID != "" && cur.authID != "" {
		causes, keys = append(causes, fmt.Sprintf("CPA 选用的凭据变了（%s → %s）；多条凭据轮询时可开启 routing.session-affinity", shortID(prev.authID), shortID(cur.authID))), append(keys, "auth")
	}
	if prev.insSHA != cur.insSHA && prev.insSHA != "" && cur.insSHA != "" {
		causes, keys = append(causes, fmt.Sprintf("渠道注入的 instructions 变了（%s → %s），前缀从头就不同", prev.insSHA, cur.insSHA)), append(keys, "instructions")
	}
	if len(causes) == 0 {
		return "渠道、凭据、注入的 instructions 都没变：最可能是渠道内部把请求分到了另一个上游账号 / 后端（缓存不跨账号共享）", "upstream-pool"
	}
	return strings.Join(causes, "；"), strings.Join(keys, "+")
}

func shortID(id string) string {
	if i := strings.LastIndexByte(id, ':'); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return truncate(id, 16)
}

func (t *sessionTracker) pruneLocked(now time.Time) {
	if len(t.sessions) <= sessionMaxCount {
		for id, seen := range t.lastSeen {
			if now.Sub(seen) > sessionMaxAge {
				delete(t.sessions, id)
				delete(t.lastSeen, id)
			}
		}
		return
	}
	ids := make([]string, 0, len(t.lastSeen))
	for id := range t.lastSeen {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return t.lastSeen[ids[i]].Before(t.lastSeen[ids[j]]) })
	for _, id := range ids[:len(ids)/4] {
		delete(t.sessions, id)
		delete(t.lastSeen, id)
	}
}

// promptItems 把请求拆成"前缀条目"并逐条哈希：工具声明、system/instructions、每条消息各算一条。
// 条目级比较对 JSON 键序、无关的顶层字段变化不敏感，比字节级前缀稳健。
func promptItems(doc any) (hashes []uint64, sizes []int) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, nil
	}
	if inner, ok := obj["request"].(map[string]any); ok { // Gemini CLI 外层包装
		obj = inner
	}
	add := func(v any) {
		if v == nil {
			return
		}
		raw, err := json.Marshal(v) // map 的键按字典序输出，结果是规范化的
		if err != nil || len(raw) <= 2 {
			return
		}
		h := fnv.New64a()
		_, _ = h.Write(raw)
		hashes, sizes = append(hashes, h.Sum64()), append(sizes, len(raw))
	}
	add(obj["tools"])
	for _, key := range []string{"system", "instructions", "systemInstruction", "system_instruction"} {
		add(obj[key])
	}
	for _, key := range []string{"messages", "input", "contents"} {
		switch list := obj[key].(type) {
		case []any:
			for _, item := range list {
				add(item)
			}
		case string:
			add(list)
		}
	}
	return hashes, sizes
}

// sessionKey 取会话标识：优先客户端的会话头，其次请求体里的缓存键 / 会话字段，最后用宿主给的会话元数据。
func sessionKey(headers map[string][]string, doc any, meta map[string]string) string {
	for _, want := range []string{"session-id", "session_id", "x-claude-code-session-id", "x-session-id", "thread-id", "conversation-id", "conversation_id"} {
		for name, values := range headers {
			if strings.EqualFold(name, want) && len(values) > 0 && strings.TrimSpace(values[0]) != "" {
				return "h:" + truncate(strings.TrimSpace(values[0]), 96)
			}
		}
	}
	if obj, ok := doc.(map[string]any); ok {
		if s := asString(obj["prompt_cache_key"]); s != "" {
			return "k:" + truncate(s, 96)
		}
		if s := asString(nestedGet(obj, "metadata", "user_id")); s != "" { // Claude Code：…_session_<uuid>
			return "u:" + truncate(s, 160)
		}
		switch conv := obj["conversation"].(type) {
		case string:
			if conv != "" {
				return "c:" + truncate(conv, 96)
			}
		case map[string]any:
			if s := asString(conv["id"]); s != "" {
				return "c:" + truncate(s, 96)
			}
		}
	}
	for _, key := range []string{"canonical_session_id", "execution_session_id"} {
		if meta[key] != "" {
			return "m:" + meta[key]
		}
	}
	return ""
}

// cachedTokens 返回上游口径的缓存读 token 数，未知返回 -1。
func (m *message) cachedTokens() int64 {
	if m == nil || m.Usage == nil {
		return -1
	}
	var v any
	switch m.Format {
	case fmtClaude:
		v = m.Usage["cache_read_input_tokens"]
	case fmtChat:
		v = nestedGet(m.Usage, "prompt_tokens_details", "cached_tokens")
	case fmtResponses:
		v = nestedGet(m.Usage, "input_tokens_details", "cached_tokens")
	case fmtGemini:
		return asInt64(m.Usage["cachedContentTokenCount"]) // protobuf JSON 省略零值：缺失就是 0
	}
	switch v.(type) {
	case json.Number, float64:
		return asInt64(v)
	}
	return -1 // 渠道没给这项统计：不能当成"零命中"
}

func cacheFinding(v *cacheVerdict, base finding) finding {
	f := base
	f.Category, f.Rule, f.Severity = catCost, "cache-lost", sevNotice
	if v.Lost >= 10000 || strings.Contains(v.causeKey, "instructions") {
		f.Severity = sevWarn
	}
	f.Title = "同一会话的提示词缓存失效，前缀被重新计费"
	f.Detail = "本轮请求与上一轮共享 " + fmt.Sprint(v.Shared) + "% 的前缀、间隔仅 " + fmt.Sprint(v.GapSec) + " 秒，本应命中缓存。未命中的部分 OpenAI 系按原价计费；Claude 系还要再付一次缓存写入的溢价。原因：" + v.Cause + "。"
	f.Evidence = fmt.Sprintf("预期缓存读 ≈ %d token，实际 %d，损失 ≈ %d token", v.Expected, v.Actual, v.Lost)
	f.Key = findingKey(f.Rule, base.Channel, v.causeKey)
	return f
}
