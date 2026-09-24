package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// codexEnv 与 codex-tui 实际发出的 environment_context 一致（VPS 记录，2026-09-24）。
func codexEnv(date, zone string) string {
	return "<environment_context>\n  <cwd>/root/code</cwd>\n  <shell>bash</shell>\n  <current_date>" + date + "</current_date>\n  <timezone>" + zone +
		"</timezone>\n  <filesystem><workspace_roots><root>/root/code</root></workspace_roots><permission_profile type=\"disabled\"><file_system type=\"unrestricted\" /></permission_profile></filesystem>\n</environment_context>"
}

func codexBody(t *testing.T, session string, envs ...string) []byte {
	t.Helper()
	input := []any{
		map[string]any{"type": "message", "role": "developer", "content": []any{map[string]any{"type": "input_text", "text": "base prompt"}}},
		map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "# AGENTS.md instructions"}, map[string]any{"type": "input_text", "text": envs[0]}}},
		map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": "写个测试 <timezone>Asia/Shanghai</timezone>"}}},
		// 工具输出里出现同样的标签（例如在开发本插件时读测试数据），不能被改写
		map[string]any{"type": "function_call_output", "call_id": "c1", "output": envs[0]},
		map[string]any{"type": "function_call_output", "call_id": "c2", "output": []any{map[string]any{"type": "input_text", "text": envs[0]}}},
		// assistant 复述了同样的文本：同样不能被改写
		map[string]any{"type": "message", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": envs[0]}}},
		map[string]any{"type": "message", "role": "assistant", "content": envs[0]},
	}
	for _, env := range envs[1:] {
		input = append(input, map[string]any{"type": "message", "role": "user", "content": []any{map[string]any{"type": "input_text", "text": env}}})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // 与 Codex（serde_json）一致：不转义 <>
	if err := enc.Encode(map[string]any{"model": "gpt-5.6-sol", "stream": true, "prompt_cache_key": session, "input": input}); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(buf.Bytes())
}

func interceptBefore(t *testing.T, id string, body []byte) []byte {
	t.Helper()
	env := call(t, methodRequestInterceptBefore, requestInterceptRequest{RequestID: id, SourceFormat: "openai-response", Model: "gpt-5.6-sol", Stream: true, Headers: http.Header{}, Body: body})
	var res requestInterceptResult
	if err := json.Unmarshal(env.Result, &res); err != nil {
		t.Fatalf("bad intercept result %s: %v", env.Result, err)
	}
	return res.Body
}

func setClock(t *testing.T, s string) {
	t.Helper()
	now, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	currentInspector().env.now = func() time.Time { return now }
}

func TestEnvContextRewrittenToTargetZone(t *testing.T) {
	setup(t, "rewrite_env_timezone: America/Los_Angeles")
	setClock(t, "2026-09-25T01:27:35+08:00") // 洛杉矶此时是 9 月 24 日 10:27（PDT）
	body := codexBody(t, "s1", codexEnv("2026-09-25", "Asia/Shanghai"))
	out := interceptBefore(t, "e1", body)
	if out == nil {
		t.Fatal("request body was not rewritten")
	}
	want := codexEnv("2026-09-24", "America/Los_Angeles")
	if !bytes.Contains(out, jsonString(want)) {
		t.Fatalf("environment_context not rewritten as expected:\n%s", out)
	}
	// 只替换 user 消息里的那一段：工具输出与对话正文保持原样，其余字节不变
	orig := jsonString(codexEnv("2026-09-25", "Asia/Shanghai"))
	if bytes.Count(out, orig) != 4 || !bytes.Contains(out, []byte("写个测试 <timezone>Asia/Shanghai</timezone>")) {
		t.Fatalf("content outside environment_context must stay untouched:\n%s", out)
	}
	if got := bytes.Replace(out, jsonString(want), orig, 1); !bytes.Equal(got, body) {
		t.Fatalf("rewrite changed other bytes:\n got %s\nwant %s", got, body)
	}
	if !json.Valid(out) {
		t.Fatalf("rewritten body is not valid JSON: %s", out)
	}

	// 宿主选定凭据后传来的是改写版：客户端原文仍是记录里的 client_request
	call(t, methodRequestInterceptAfter, requestInterceptRequest{RequestID: "e1", SourceFormat: "openai-response", ToFormat: "openai-response", Model: "gpt-5.6-sol", Stream: true, Body: out})
	call(t, methodRequestComplete, requestCompletion{RequestID: "e1", Outcome: "succeeded", StatusCode: 200, StartedAt: time.Now(), CompletedAt: time.Now()})
	currentInspector().finalizeDue(true)
	_, rawDetail, err := currentInspector().store.load("e1")
	if err != nil {
		t.Fatal(err)
	}
	var det detail
	if err := json.Unmarshal(rawDetail, &det); err != nil {
		t.Fatal(err)
	}
	client, _ := json.Marshal(det.ClientRequest.JSON)
	if !strings.Contains(string(client), "Asia/Shanghai") || strings.Contains(string(client), "America/Los_Angeles") {
		t.Fatalf("client_request must keep the client's original body: %s", client)
	}
	if len(det.Rewrites) != 1 || det.Rewrites[0] != "timezone Asia/Shanghai → America/Los_Angeles，current_date 2026-09-25 → 2026-09-24" {
		t.Fatalf("rewrite notes: %q", det.Rewrites)
	}
}

// 同一会话里的历史 environment_context 必须每轮改写成同样的字节，否则会破坏前缀缓存。
func TestEnvContextRewriteIsPinnedPerSession(t *testing.T) {
	setup(t, "rewrite_env_timezone: America/Los_Angeles")
	first := codexEnv("2026-09-24", "Asia/Shanghai")
	setClock(t, "2026-09-24T10:00:00+08:00") // 洛杉矶 9 月 23 日
	out1 := interceptBefore(t, "p1", codexBody(t, "s1", first))
	if !bytes.Contains(out1, []byte("<current_date>2026-09-23</current_date>")) {
		t.Fatalf("first turn: %s", out1)
	}
	// 洛杉矶跨过零点、上海也跨过零点后，Codex 追加一段新日期的 environment_context
	second := strings.Replace(first, "2026-09-24", "2026-09-25", 1)
	setClock(t, "2026-09-25T00:30:00+08:00") // 洛杉矶 9 月 24 日 09:30
	out2 := interceptBefore(t, "p2", codexBody(t, "s1", first, second))
	if !bytes.Contains(out2, jsonString(codexEnv("2026-09-23", "America/Los_Angeles"))) {
		t.Fatalf("history block must keep its first rewrite: %s", out2)
	}
	if !bytes.Contains(out2, jsonString(codexEnv("2026-09-24", "America/Los_Angeles"))) {
		t.Fatalf("new block must use the current Los Angeles date: %s", out2)
	}
	// 另一个会话里同样的原文按自己的首次时间换算
	out3 := interceptBefore(t, "p3", codexBody(t, "s2", second))
	if !bytes.Contains(out3, []byte("<current_date>2026-09-24</current_date>")) {
		t.Fatalf("other session: %s", out3)
	}
}

func TestEnvTargetDate(t *testing.T) {
	la, _ := time.LoadLocation("America/Los_Angeles")
	now, _ := time.Parse(time.RFC3339, "2026-09-25T20:00:00+08:00") // 洛杉矶 9 月 25 日 05:00
	for _, c := range []struct{ src, zone, want string }{
		{"2026-09-25", "Asia/Shanghai", "2026-09-25"}, // 客户端的"今天"：取洛杉矶当前日期
		{"2026-09-23", "Asia/Shanghai", "2026-09-22"}, // 更早的日期：按上海正午换算
		{"2026-09-25", "Mars/Olympus", "2026-09-25"},  // 未知时区：只能取当前日期
	} {
		if got := envTargetDate(c.src, c.zone, la, now); got != c.want {
			t.Fatalf("envTargetDate(%s, %s) = %s, want %s", c.src, c.zone, got, c.want)
		}
	}
}

func TestEnvContextLeftAloneWhenNotApplicable(t *testing.T) {
	setup(t, "")
	if out := interceptBefore(t, "n1", codexBody(t, "s1", codexEnv("2026-09-25", "Asia/Shanghai"))); out != nil {
		t.Fatalf("rewrite must be off by default: %s", out)
	}
	setup(t, "rewrite_env_timezone: America/Los_Angeles")
	if out := interceptBefore(t, "n2", codexBody(t, "s1", codexEnv("2026-09-25", "America/Los_Angeles"))); out != nil {
		t.Fatalf("already in the target zone: %s", out)
	}
	noZone := "<environment_context>\n  <cwd>/root</cwd>\n  <current_date>2026-09-25</current_date>\n</environment_context>"
	if out := interceptBefore(t, "n3", codexBody(t, "s1", noZone)); out != nil {
		t.Fatalf("no <timezone>: %s", out)
	}
	// 客户端把 < 转义成 unicode 转义序列：预筛找不到标签，不改写
	escaped := bytes.ReplaceAll(codexBody(t, "s1", codexEnv("2026-09-25", "Asia/Shanghai")), []byte("<"), []byte{'\\', 'u', '0', '0', '3', 'c'})
	if out := interceptBefore(t, "n4", escaped); out != nil {
		t.Fatalf("escaped body must be left alone: %s", out)
	}
}

func TestInvalidRewriteZoneIsRejected(t *testing.T) {
	for _, zone := range []string{"California", "Local"} {
		if _, err := parseConfig([]byte("rewrite_env_timezone: " + zone)); err == nil {
			t.Fatalf("%s must be rejected", zone)
		}
	}
	cfg, err := parseConfig([]byte("rewrite_env_timezone: ' America/Los_Angeles '"))
	if err != nil || cfg.RewriteEnvTimezone != "America/Los_Angeles" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}

// 请求体带缩进、键值间有空白时，按字节区间定位仍然准确。
func TestEnvContextRewriteOnIndentedBody(t *testing.T) {
	setup(t, "rewrite_env_timezone: America/Los_Angeles")
	setClock(t, "2026-09-25T01:27:35+08:00")
	var v any
	if err := json.Unmarshal(codexBody(t, "s1", codexEnv("2026-09-25", "Asia/Shanghai")), &v); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	body := buf.Bytes()
	out := interceptBefore(t, "i1", body)
	if !json.Valid(out) || bytes.Count(out, []byte("America/Los_Angeles")) != 1 || bytes.Count(out, []byte("Asia/Shanghai")) != bytes.Count(body, []byte("Asia/Shanghai"))-1 {
		t.Fatalf("indented body not rewritten exactly once:\n%s", out)
	}
}

// 只改 environment_context 内部：同一文本块后面的正文里的同名标签不动。
func TestEnvContextTagsOutsideBlockAreIgnored(t *testing.T) {
	la, _ := time.LoadLocation("America/Los_Angeles")
	now, _ := time.Parse(time.RFC3339, "2026-09-25T01:27:35+08:00")
	noZone := "<environment_context><cwd>/root/code</cwd></environment_context>\nExplain <timezone>Asia/Shanghai</timezone>."
	if got, _ := rewriteEnvText(noZone, "America/Los_Angeles", la, now); got != noZone {
		t.Fatalf("tags after the block must be ignored: %q", got)
	}
	noDate := "<environment_context><timezone>Asia/Shanghai</timezone></environment_context>\n<current_date>2026-09-25</current_date>"
	want := "<environment_context><timezone>America/Los_Angeles</timezone></environment_context>\n<current_date>2026-09-25</current_date>"
	if got, _ := rewriteEnvText(noDate, "America/Los_Angeles", la, now); got != want {
		t.Fatalf("date after the block must be ignored: %q", got)
	}
	unclosed := "<environment_context><timezone>Asia/Shanghai</timezone>"
	if got, _ := rewriteEnvText(unclosed, "America/Los_Angeles", la, now); got != unclosed {
		t.Fatalf("unclosed block must be left alone: %q", got)
	}
}
