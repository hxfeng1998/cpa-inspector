package main

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// conversation 生成一个 n 轮的 Responses 形态请求；轮次越多前缀越长，前 n-1 轮与上一请求完全相同。
func conversation(t *testing.T, n int, salt string) any {
	t.Helper()
	var items []string
	items = append(items, fmt.Sprintf(`{"type":"message","role":"developer","content":[{"type":"input_text","text":"base prompt %s %s"}]}`, salt, strings.Repeat("x", 4000)))
	for i := 0; i < n; i++ {
		items = append(items, fmt.Sprintf(`{"type":"message","role":"user","content":[{"type":"input_text","text":"turn %d %s"}]}`, i, strings.Repeat("y", 600)))
	}
	doc, ok := decodeJSON([]byte(`{"model":"m","prompt_cache_key":"sess-1","client_metadata":{"turn":"` + fmt.Sprint(n) + `"},"input":[` + strings.Join(items, ",") + `]}`))
	if !ok {
		t.Fatal("bad fixture")
	}
	return doc
}

func turnOf(t *testing.T, id string, doc any, at time.Time, total, cached int64) sessionTurn {
	t.Helper()
	turn := sessionTurn{reqID: id, started: at, completed: at.Add(2 * time.Second), model: "m", channel: "relay.example", authID: "codex:apikey:aaaa", insSHA: "none", total: total, cached: cached}
	turn.items, turn.sizes = promptItems(doc)
	return turn
}

func TestCacheLostWithinSessionIsReported(t *testing.T) {
	tr, t0 := newSessionTracker(), time.Now()
	if v := tr.observe("s", turnOf(t, "r1", conversation(t, 3, ""), t0, 12000, 0)); v != nil {
		t.Fatalf("first turn of a session has no predecessor: %+v", v)
	}
	if v := tr.observe("s", turnOf(t, "r2", conversation(t, 4, ""), t0.Add(20*time.Second), 12400, 11776)); v != nil {
		t.Fatalf("a healthy cache hit must not be reported: %+v", v)
	}
	v := tr.observe("s", turnOf(t, "r3", conversation(t, 5, ""), t0.Add(40*time.Second), 12800, 0))
	if v == nil || v.PrevID != "r2" || v.Lost < 10000 || v.causeKey != "upstream-pool" || v.Shared < 99 {
		t.Fatalf("cache loss with nothing changed on our side must blame the upstream pool: %+v", v)
	}
	f := cacheFinding(v, finding{Channel: "relay.example"})
	if f.Rule != "cache-lost" || f.Category != catCost || f.Severity != sevWarn || !strings.Contains(f.Evidence, "损失") {
		t.Fatalf("bad finding: %+v", f)
	}
}

func TestCacheLossCauseAttribution(t *testing.T) {
	t0 := time.Now()
	for name, mutate := range map[string]func(*sessionTurn){
		"channel":      func(c *sessionTurn) { c.channel = "other.example" },
		"auth":         func(c *sessionTurn) { c.authID = "codex:apikey:bbbb" },
		"instructions": func(c *sessionTurn) { c.insSHA = "f912819f3b" },
	} {
		tr := newSessionTracker()
		tr.observe("s", turnOf(t, "r1", conversation(t, 3, ""), t0, 12000, 0))
		cur := turnOf(t, "r2", conversation(t, 4, ""), t0.Add(30*time.Second), 12400, 0)
		mutate(&cur)
		if v := tr.observe("s", cur); v == nil || v.causeKey != name {
			t.Errorf("%s: want cause %q, got %+v", name, name, v)
		}
	}
}

func TestCacheLossIsNotReportedWhenMissIsLegitimate(t *testing.T) {
	t0 := time.Now()
	cases := map[string]sessionTurn{
		"expired (gap beyond TTL)":            turnOf(t, "r2", conversation(t, 4, ""), t0.Add(cacheTTL+time.Minute), 12400, 0),
		"different prefix (new conversation)": turnOf(t, "r2", conversation(t, 4, "compacted"), t0.Add(30*time.Second), 12400, 0),
		"partial hit above the floor":         turnOf(t, "r2", conversation(t, 4, ""), t0.Add(30*time.Second), 12400, 7000),
	}
	for name, cur := range cases {
		tr := newSessionTracker()
		tr.observe("s", turnOf(t, "r1", conversation(t, 3, ""), t0, 12000, 0))
		if v := tr.observe("s", cur); v != nil {
			t.Errorf("%s: must not be reported: %+v", name, v)
		}
	}
	// 上一轮太短、不足以缓存
	tr := newSessionTracker()
	tr.observe("s", turnOf(t, "r1", conversation(t, 3, ""), t0, 900, 0))
	if v := tr.observe("s", turnOf(t, "r2", conversation(t, 4, ""), t0.Add(30*time.Second), 1100, 0)); v != nil {
		t.Errorf("short prompts are not cacheable: %+v", v)
	}
	// 并行请求：上一条还没结束，缓存未必就绪
	tr = newSessionTracker()
	p := turnOf(t, "r1", conversation(t, 3, ""), t0, 12000, 0)
	p.completed = t0.Add(60 * time.Second)
	tr.observe("s", p)
	if v := tr.observe("s", turnOf(t, "r2", conversation(t, 4, ""), t0.Add(1*time.Second), 12400, 0)); v != nil {
		t.Errorf("concurrent requests must not be compared: %+v", v)
	}
	// 不同会话互不影响
	tr = newSessionTracker()
	tr.observe("a", turnOf(t, "r1", conversation(t, 3, ""), t0, 12000, 0))
	if v := tr.observe("b", turnOf(t, "r2", conversation(t, 4, ""), t0.Add(30*time.Second), 12400, 0)); v != nil {
		t.Errorf("sessions are independent: %+v", v)
	}
}

// Codex 会在同一会话里穿插"生成标题"之类的旁路请求：要和公共前缀最长的那一轮比，而不是简单取上一条。
func TestCachePredecessorIsLongestSharedPrefix(t *testing.T) {
	tr, t0 := newSessionTracker(), time.Now()
	tr.observe("s", turnOf(t, "main1", conversation(t, 3, ""), t0, 12000, 0))
	side := turnOf(t, "title", conversation(t, 1, ""), t0.Add(5*time.Second), 9000, 8000) // 旁路请求，前缀更短
	tr.observe("s", side)
	v := tr.observe("s", turnOf(t, "main2", conversation(t, 4, ""), t0.Add(30*time.Second), 12400, 0))
	if v == nil || v.PrevID != "main1" {
		t.Fatalf("must compare against the turn sharing the longest prefix: %+v", v)
	}
}

func TestSessionKeyPrecedence(t *testing.T) {
	doc, _ := decodeJSON([]byte(`{"prompt_cache_key":"pck-1","metadata":{"user_id":"user_x_session_y"}}`))
	if got := sessionKey(map[string][]string{"Session-Id": {"abc"}}, doc, nil); got != "h:abc" {
		t.Errorf("session header wins: %q", got)
	}
	if got := sessionKey(map[string][]string{"User-Agent": {"x"}}, doc, nil); got != "k:pck-1" {
		t.Errorf("then prompt_cache_key: %q", got)
	}
	claude, _ := decodeJSON([]byte(`{"metadata":{"user_id":"user_x_session_y"}}`))
	if got := sessionKey(nil, claude, nil); got != "u:user_x_session_y" {
		t.Errorf("then Claude Code metadata.user_id: %q", got)
	}
	if got := sessionKey(nil, nil, map[string]string{"canonical_session_id": "c1"}); got != "m:c1" {
		t.Errorf("finally host metadata: %q", got)
	}
	// 顶层无关字段变化（client_metadata.turn）不影响前缀条目
	a, _ := promptItems(conversation(t, 3, ""))
	b, _ := promptItems(conversation(t, 4, ""))
	if len(b) != len(a)+1 || a[len(a)-1] != b[len(a)-1] {
		t.Errorf("prefix items must be stable across turns: %d vs %d", len(a), len(b))
	}
}
