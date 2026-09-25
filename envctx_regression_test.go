package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func auditRewriter(t *testing.T, dir string, clock *time.Time) *envRewriter {
	t.Helper()
	r := newEnvRewriter()
	r.configure("America/Los_Angeles", dir)
	r.now = func() time.Time { return *clock }
	return r
}

func auditTime(t *testing.T, value string) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func auditBody(t *testing.T, session, kind, text string) []byte {
	t.Helper()
	item := map[string]any{"role": "user", "content": []any{map[string]any{"type": "input_text", "text": text}}}
	if kind != "" {
		item["internal_chat_message_metadata_passthrough"] = map[string]any{"content_item_kinds": []string{kind}}
	}
	body := map[string]any{"input": []any{item}}
	if session != "" {
		body["client_metadata"] = map[string]any{"session_id": session}
	}
	raw, err := json.Marshal(body) // 默认转义 HTML，覆盖真实中间层重新序列化的情况。
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func auditTexts(t *testing.T, body []byte) []string {
	t.Helper()
	var req struct {
		Input []struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"input"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, item := range req.Input {
		for _, content := range item.Content {
			out = append(out, content.Text)
		}
	}
	return out
}

func TestEnvTargetMidnightPreservesHistoryAndAddsToday(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	body := auditBody(t, "s1", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai"))
	first, _ := r.rewrite(body, nil)
	history := auditTexts(t, first)
	if len(history) != 1 || !strings.Contains(history[0], "2026-09-24") {
		t.Fatalf("first: %s", first)
	}
	now = now.Add(time.Hour)
	second, _ := r.rewrite(body, nil)
	texts := auditTexts(t, second)
	if len(texts) != 2 || texts[0] != history[0] || !strings.Contains(texts[1], "2026-09-25") {
		t.Fatalf("midnight: %s", second)
	}
	// 同日重试、客户端重发同一历史，都得到相同的更新，不依赖请求成功回调。
	retry, _ := r.rewrite(body, nil)
	if !bytes.Equal(second, retry) {
		t.Fatal("retry differs")
	}
	if twice, _ := r.rewrite(second, nil); twice != nil {
		t.Fatalf("duplicate update: %s", twice)
	}
}

func TestEnvExampleAndUnmarkedLegacyStayUntouched(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	for _, kind := range []string{"user.text", "", "future.kind"} {
		body := auditBody(t, "s1", kind, codexEnv("2026-09-25", "Asia/Shanghai"))
		if out, _ := r.rewrite(body, nil); out != nil {
			t.Fatalf("kind %q modified: %s", kind, out)
		}
	}
}

func TestEnvContentKindUsesOriginalContentIndex(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	text := codexEnv("2026-09-25", "Asia/Shanghai")
	raw, _ := json.Marshal(map[string]any{
		"prompt_cache_key": "s1", "input": []any{map[string]any{
			"role": "user", "content": []any{
				map[string]any{"type": "input_image", "image_url": "data:image/png;base64,AA=="},
				map[string]any{"type": "input_text", "text": text},
				map[string]any{"type": "input_text", "text": text},
			},
			"internal_chat_message_metadata_passthrough": map[string]any{"content_item_kinds": []string{"user.image", "user.text", envContentKind}},
		}},
	})
	out, _ := r.rewrite(raw, nil)
	texts := auditTexts(t, out)
	if len(texts) != 3 || texts[1] != text || !strings.Contains(texts[2], "America/Los_Angeles") {
		t.Fatalf("wrong index: %s", out)
	}
}

func TestEnvClientMetadataSessionsDoNotSharePins(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	text := codexEnv("2026-09-25", "Asia/Shanghai")
	r.rewrite(auditBody(t, "one", envContentKind, text), nil)
	now = now.Add(time.Hour)
	out, _ := r.rewrite(auditBody(t, "two", envContentKind, text), nil)
	texts := auditTexts(t, out)
	if len(texts) != 1 || !strings.Contains(texts[0], "2026-09-25") {
		t.Fatalf("session collision: %s", out)
	}
}

func TestEnvAnonymousHistoryIsNeverPinned(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	text := codexEnv("2026-09-25", "Asia/Shanghai")
	body := auditBody(t, "", envContentKind, text)
	for _, date := range []string{"2026-09-24", "2026-09-25"} {
		out, _ := r.rewrite(body, nil)
		texts := auditTexts(t, out)
		if len(texts) != 2 || texts[0] != text || !strings.Contains(texts[1], date) {
			t.Fatalf("anonymous: %s", out)
		}
		now = now.Add(time.Hour)
	}
	if len(r.sessions) != 0 {
		t.Fatal("anonymous session cached")
	}
}

func TestEnvRestartAndMemoryEvictionPreserveMapping(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	dir := t.TempDir()
	r := auditRewriter(t, dir, &now)
	body := auditBody(t, "s1", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai"))
	first, _ := r.rewrite(body, nil)
	history := auditTexts(t, first)[0]
	now = now.Add(10 * 24 * time.Hour) // 超过原实现的 72 小时 TTL。
	r = auditRewriter(t, dir, &now)
	for i := 0; i < 2; i++ {
		out, _ := r.rewrite(body, nil)
		texts := auditTexts(t, out)
		if len(texts) != 2 || texts[0] != history || !strings.Contains(texts[1], "2026-10-04") {
			t.Fatalf("restored history: %s", out)
		}
		r.sessions = make(map[string]*envSession) // 模拟内存缓存淘汰。
	}
}

func TestEnvUnknownHistoricalDatesAreNotGuessed(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	dir := t.TempDir()
	r := auditRewriter(t, dir, &now)
	for _, src := range []struct{ date, zone string }{
		{"2026-09-23", "Asia/Shanghai"}, {"2026-09-25", "Mars/Olympus"},
		{"2026-03-08", "America/New_York"}, {"2026-11-01", "America/New_York"},
	} {
		text := codexEnv(src.date, src.zone)
		body := auditBody(t, "s1", envContentKind, text)
		out, _ := r.rewrite(body, nil)
		texts := auditTexts(t, out)
		if len(texts) != 2 || texts[0] != text || !strings.Contains(texts[1], "America/Los_Angeles") {
			t.Fatalf("historical date guessed: %s", out)
		}
	}
}

func TestEnvContinuationAfterRestartUsesHostIdentity(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	dir := t.TempDir()
	r := auditRewriter(t, dir, &now)
	host := map[string]any{"canonical_session_id": "session", "caller_scope": "caller"}
	r.rewrite(auditBody(t, "", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai")), nil, host)
	now = now.Add(time.Hour)
	r = auditRewriter(t, dir, &now)
	body := []byte(`{"previous_response_id":"resp_1","input":[{"type":"function_call_output","call_id":"c1","output":"done"}]}`)
	out, _ := r.rewrite(body, nil, host)
	texts := auditTexts(t, out)
	if len(texts) != 1 || !strings.Contains(texts[0], "2026-09-25") || !bytes.Contains(out, []byte(`"previous_response_id":"resp_1"`)) {
		t.Fatalf("continuation: %s", out)
	}
	if out, _ := r.rewrite(body, nil, map[string]any{"canonical_session_id": "other"}); out != nil {
		t.Fatal("unknown continuation modified")
	}
	if out, _ := r.rewrite(body, nil, map[string]any{"canonical_session_id": "session", "caller_scope": "other"}); out != nil {
		t.Fatal("caller scopes collided")
	}
}

func TestEnvPersistenceFailureDoesNotPublishMapping(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	dir := t.TempDir()
	r := auditRewriter(t, dir, &now)
	// 使用文件挡住目录，即使测试以 root 运行也会稳定失败。
	blocked := filepath.Join(dir, "env-timezone")
	if err := os.WriteFile(blocked, []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	body := auditBody(t, "s1", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai"))
	if out, _ := r.rewrite(body, nil); out != nil {
		t.Fatal("unpersisted rewrite published")
	}
	if len(r.sessions) != 0 {
		t.Fatal("failed mapping cached")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	out, _ := r.rewrite(body, nil)
	if out == nil {
		t.Fatal("did not recover")
	}
	// 状态损坏时也不能用当前时刻覆盖既有映射。
	var doc map[string]any
	json.Unmarshal(body, &doc)
	path := r.sessionPath(envSessionKey(nil, doc, nil))
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	r = auditRewriter(t, dir, &now)
	if out, _ := r.rewrite(body, nil); out != nil {
		t.Fatal("corrupt state silently replaced")
	}
}

func TestEnvIdentityKeepsLongIDsAndSeparatesThreads(t *testing.T) {
	prefix := strings.Repeat("a", 160)
	one := envSessionKey(http.Header{"Session-Id": {prefix + "one"}}, nil, nil)
	two := envSessionKey(http.Header{"Session-Id": {prefix + "two"}}, nil, nil)
	if one == two {
		t.Fatal("IDs truncated")
	}
	a := envSessionKey(nil, map[string]any{"client_metadata": map[string]any{"session_id": "parent", "thread_id": "a"}}, nil)
	b := envSessionKey(nil, map[string]any{"client_metadata": map[string]any{"session_id": "parent", "thread_id": "b"}}, nil)
	if a == b {
		t.Fatal("threads share pins")
	}
}

func TestEnvConfigureConcurrentWithRewrite(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	dir := t.TempDir()
	r := auditRewriter(t, dir, &now)
	body := auditBody(t, "s1", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai"))
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			r.configure("", dir)
			r.configure("America/Los_Angeles", dir)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			if out, _ := r.rewrite(body, nil); out != nil && !json.Valid(out) {
				t.Error("invalid JSON")
			}
		}
	}()
	wg.Wait()
}

func TestEnvRPCUsesMetadataAndRejectsOtherFormats(t *testing.T) {
	setup(t, "rewrite_env_timezone: America/Los_Angeles")
	setClock(t, "2026-09-25T06:30:00Z")
	req := requestInterceptRequest{RequestID: "meta1", SourceFormat: "openai-response", Metadata: map[string]any{"canonical_session_id": "host-s1"}, Body: auditBody(t, "", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai"))}
	first := call(t, methodRequestInterceptBefore, req)
	var res requestInterceptResult
	if err := json.Unmarshal(first.Result, &res); err != nil || len(auditTexts(t, res.Body)) != 1 {
		t.Fatalf("host metadata not used: %s", first.Result)
	}
	req.SourceFormat = "claude"
	other := call(t, methodRequestInterceptBefore, req)
	res = requestInterceptResult{}
	if err := json.Unmarshal(other.Result, &res); err != nil {
		t.Fatal(err)
	}
	if res.Body != nil {
		t.Fatal("non-Responses request modified")
	}
}

func TestEnvTargetZoneAlreadyMatchesButDateIsStale(t *testing.T) {
	now := auditTime(t, "2026-09-25T08:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	text := codexEnv("2026-09-24", "America/Los_Angeles")
	out, _ := r.rewrite(auditBody(t, "same-zone", envContentKind, text), nil)
	texts := auditTexts(t, out)
	if len(texts) != 2 || texts[0] != text || !strings.Contains(texts[1], "2026-09-25") {
		t.Fatalf("stale target date: %s", out)
	}
}

func TestEnvReconfigureRestoresPerZoneState(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	dir := t.TempDir()
	r := auditRewriter(t, dir, &now)
	body := auditBody(t, "s1", envContentKind, codexEnv("2026-09-25", "Asia/Shanghai"))
	first, _ := r.rewrite(body, nil)
	history := auditTexts(t, first)[0]
	now = now.Add(time.Hour)
	r.configure("", dir)
	if out, _ := r.rewrite(body, nil); out != nil {
		t.Fatal("disabled rewriter modified request")
	}
	r.configure("Etc/UTC", dir)
	out, _ := r.rewrite(body, nil)
	if !strings.Contains(auditTexts(t, out)[0], "Etc/UTC") {
		t.Fatal("zone not applied")
	}
	r.configure("America/Los_Angeles", dir)
	out, _ = r.rewrite(body, nil)
	if auditTexts(t, out)[0] != history {
		t.Fatal("old zone mapping lost")
	}
	// 换目录明确作为独立状态空间，不能继续使用旧目录的内存映射。
	r.configure("America/Los_Angeles", t.TempDir())
	out, _ = r.rewrite(body, nil)
	if strings.Contains(auditTexts(t, out)[0], "2026-09-24") {
		t.Fatal("state leaked across data directories")
	}
}

func TestEnvTargetDateAcrossDST(t *testing.T) {
	la, err := time.LoadLocation("America/Los_Angeles")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ instant, sourceDate, want string }{
		{"2026-03-08T07:30:00Z", "2026-03-08", "2026-03-07"},
		{"2026-03-08T10:30:00Z", "2026-03-08", "2026-03-08"},
		{"2026-11-01T06:30:00Z", "2026-11-01", "2026-10-31"},
		{"2026-11-01T09:30:00Z", "2026-11-01", "2026-11-01"},
	} {
		if got := envTargetDate(c.sourceDate, "Asia/Shanghai", la, auditTime(t, c.instant)); got != c.want {
			t.Errorf("%s: got %s want %s", c.instant, got, c.want)
		}
	}
}

func TestEnvUnmarkedCodexWireRequest(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	headers := http.Header{"Originator": {"codex-tui"}, "User-Agent": {"codex-tui/0.156.1 (Windows)"}}
	text := codexEnv("2026-09-25", "Asia/Shanghai")
	body := auditBody(t, "wire-session", "", text)
	first, _ := r.rewrite(body, headers)
	if first == nil || !strings.Contains(auditTexts(t, first)[0], "America/Los_Angeles") {
		t.Fatalf("wire request skipped: %s", first)
	}
	now = now.Add(time.Hour)
	second, _ := r.rewrite(body, headers)
	texts := auditTexts(t, second)
	if len(texts) != 2 || texts[0] != auditTexts(t, first)[0] {
		t.Fatalf("midnight: %s", second)
	}
	for _, example := range []string{text + "\n请解释", strings.Replace(text, "<cwd>/root/code</cwd>", "<example>demo</example>", 1)} {
		if out, _ := r.rewrite(auditBody(t, "new-example", "", example), headers); out != nil {
			t.Fatalf("example modified: %s", out)
		}
	}
	if out, _ := r.rewrite(auditBody(t, "explicit-user", "user.text", text), headers); out != nil {
		t.Fatal("explicit user text modified")
	}
}

func TestEnvUnmarkedClientMetadataAndDateDelta(t *testing.T) {
	now := auditTime(t, "2026-09-25T06:30:00Z")
	r := auditRewriter(t, t.TempDir(), &now)
	body := auditBody(t, "wire", "", codexEnv("2026-09-25", "Asia/Shanghai"))
	var doc map[string]any
	json.Unmarshal(body, &doc)
	client := doc["client_metadata"].(map[string]any)
	client["thread_id"] = "thread"
	client["x-codex-window-id"] = "window"
	body, _ = json.Marshal(doc)
	if out, _ := r.rewrite(body, nil); out == nil {
		t.Fatal("metadata identity skipped")
	}
	delta := "<environment_context><current_date>2026-09-25</current_date><timezone>Asia/Shanghai</timezone></environment_context>"
	if !legacyEnvContext(delta, nil, doc) || legacyEnvContext(delta, nil, nil) {
		t.Fatal("delta recognition incorrect")
	}
}
