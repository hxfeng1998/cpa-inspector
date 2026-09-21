package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 并发流的事件交错到达时，每个请求在一个 scope 里只应计一次。
func TestInterleavedStreamsCountEachRequestOnce(t *testing.T) {
	s := newSchemaStore()
	entries := []shapeEntry{{Path: "type", Type: "string", Example: "x"}}
	now := time.Now()
	for i := 0; i < 20; i++ {
		s.observe("scope", "m", "req-a", entries, 30, now)
		s.observe("scope", "m", "req-b", entries, 30, now)
	}
	sc := s.Scopes["scope"]
	if sc.Requests != 2 || sc.ModelRequests["m"] != 2 {
		t.Fatalf("requests=%d model_requests=%d, want 2/2", sc.Requests, sc.ModelRequests["m"])
	}
	if sc.Observations != 40 {
		t.Fatalf("observations=%d, want 40", sc.Observations)
	}
}

// 上游可以无限制造新字段名 / 新事件名：字段图谱的累计量必须有上限。
func TestSchemaStoreIsBounded(t *testing.T) {
	s := newSchemaStore()
	now := time.Now()
	for i := 0; i < schemaMaxFields+50; i++ {
		s.observe("scope", "m", "r", []shapeEntry{{Path: fmt.Sprintf("f%d", i), Type: "string"}}, 1, now)
	}
	if n := len(s.Scopes["scope"].Fields); n != schemaMaxFields {
		t.Fatalf("fields=%d, want %d", n, schemaMaxFields)
	}
	for i := 0; i < schemaMaxScopes+50; i++ {
		s.observe(fmt.Sprintf("scope-%d", i), "m", "r", []shapeEntry{{Path: "f", Type: "string"}}, 1, now)
	}
	if n := len(s.Scopes); n != schemaMaxScopes {
		t.Fatalf("scopes=%d, want %d", n, schemaMaxScopes)
	}
}

// 非流式 Chat Completions 的 message.tool_calls[] 不带 index，不能并成一个调用。
func TestNonStreamChatToolCallsStaySeparate(t *testing.T) {
	doc, ok := decodeJSON([]byte(`{"object":"chat.completion","model":"gpt-x","choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","tool_calls":[
		{"id":"call_1","type":"function","function":{"name":"Read","arguments":"{\"path\":\"a\"}"}},
		{"id":"call_2","type":"function","function":{"name":"Write","arguments":"{\"path\":\"b\"}"}}]}}]}`))
	if !ok {
		t.Fatal("bad fixture")
	}
	m := newMessage()
	m.feedDocument(doc)
	calls := m.toolCalls()
	if len(calls) != 2 || calls[0].Name != "Read" || calls[1].Name != "Write" || calls[1].ID != "call_2" {
		t.Fatalf("tool calls = %+v", calls)
	}
}

func TestModelTierSuffixIsAMismatch(t *testing.T) {
	for _, c := range []struct {
		requested, reported string
		mismatch            bool
	}{
		{"gpt-4o", "gpt-4o-mini", true},
		{"gpt-4.1", "gpt-4.1-nano-2025-04-14", true},
		{"gpt-5.1-codex", "gpt-5.1-codex-max", true},
		{"gemini-2.5-pro", "gemini-2.5-flash", true},
		{"claude-sonnet-4-5", "claude-sonnet-4-5-20250929", false},
		{"gpt-4o", "gpt-4o-2024-08-06", false},
		{"gemini-2.5-pro", "gemini-2.5-pro-preview-06-05", false},
		{"claude-opus-4-1-thinking", "claude-opus-4-1", false},
	} {
		if got := checkModel(c.requested, c.reported, finding{}) != nil; got != c.mismatch {
			t.Errorf("checkModel(%q, %q) mismatch=%v, want %v", c.requested, c.reported, got, c.mismatch)
		}
	}
}

// 字段图谱里的响应头示例与详情页用同一套脱敏判定；发现项证据里的机密一律打码。
func TestSecretsNeverReachSchemaOrFindingEvidence(t *testing.T) {
	if !isSensitiveHeader("X-Access-Token") || !isSensitiveHeader("Authorization") || isSensitiveHeader("X-Request-Id") {
		t.Fatal("isSensitiveHeader disagrees with redactHeaders' rules")
	}
	secret := "sk-" + strings.Repeat("a1B2", 12)
	ev := driftEvent{Kind: "new_field", Scope: "upstream_response|chat", Path: "debug_token", Type: "string", Example: secret}
	ins := &inspector{findings: make(map[string]*aggFinding)}
	ins.report(nil, driftFinding(ev, finding{}))
	for _, f := range ins.findings {
		if strings.Contains(f.Evidence, secret) {
			t.Fatalf("evidence leaks the secret: %s", f.Evidence)
		}
		if !strings.Contains(f.Evidence, "debug_token") {
			t.Fatalf("evidence lost its context: %s", f.Evidence)
		}
	}
}

// PEM 的检测规则只匹配 BEGIN 行，打码必须覆盖整个密钥块（证据被截断、没有 END 行时也一样）。
func TestPEMBodyIsMasked(t *testing.T) {
	body := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"
	for _, text := range []string{
		"key = -----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY----- tail",
		"key = -----BEGIN PRIVATE KEY-----\n" + body, // 被 truncate 截断
	} {
		got := maskSecretsIn(text)
		if strings.Contains(got, body) || !strings.HasPrefix(got, "key = ") {
			t.Fatalf("pem not masked: %s", got)
		}
	}
	if got := maskSecretsIn("a -----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY----- tail"); !strings.HasSuffix(got, " tail") {
		t.Fatalf("masked past the END marker: %s", got)
	}
}

// 渠道没给缓存统计 ≠ 零命中。
func TestMissingCacheStatsAreUnknown(t *testing.T) {
	usage := func(raw string) map[string]any {
		doc, _ := decodeJSON([]byte(raw))
		return doc.(map[string]any)
	}
	for _, c := range []struct {
		format, usage string
		want          int64
	}{
		{fmtChat, `{"prompt_tokens":9000}`, -1},
		{fmtChat, `{"prompt_tokens":9000,"prompt_tokens_details":{"cached_tokens":0}}`, 0},
		{fmtResponses, `{"input_tokens":9000,"input_tokens_details":{"cached_tokens":8000}}`, 8000},
		{fmtClaude, `{"input_tokens":9000}`, -1},
		{fmtGemini, `{"promptTokenCount":9000}`, 0},
	} {
		m := &message{Format: c.format, Usage: usage(c.usage)}
		if got := m.cachedTokens(); got != c.want {
			t.Errorf("%s %s: cachedTokens=%d, want %d", c.format, c.usage, got, c.want)
		}
	}
}

// 记录按完成顺序入库，但索引始终按开始时间排序：后开始先完成的请求不应排到前面去，也不应先被淘汰。
func TestStoreKeepsStartOrder(t *testing.T) {
	st := openStore(t.TempDir(), 2, 1<<30)
	base := time.Now()
	save := func(id string, startedAfter time.Duration) {
		st.save(&summary{ID: id, StartedAt: base.Add(startedAfter)}, &detail{})
	}
	save("b", 2*time.Second)
	save("a", 1*time.Second) // 先开始、后完成
	if got := st.summaries(); got[0].ID != "b" || got[1].ID != "a" {
		t.Fatalf("order = %s,%s; want b,a", got[0].ID, got[1].ID)
	}
	save("c", 3*time.Second)
	if got := st.summaries(); len(got) != 2 || got[0].ID != "c" || got[1].ID != "b" {
		t.Fatalf("after prune = %+v; want c,b", got)
	}
}

// 数据目录存在但写不进去时，详情退回内存保存，而不是只剩一个空对象。
func TestDetailSurvivesFailedDiskWrite(t *testing.T) {
	dir := t.TempDir()
	st := openStore(dir, 10, 1<<30)
	records := filepath.Join(dir, "records")
	if err := os.RemoveAll(records); err != nil { // 让后续写入必然失败（root 下 chmod 不起作用）
		t.Fatal(err)
	}
	if err := os.WriteFile(records, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	st.save(&summary{ID: "r1", StartedAt: time.Now()}, &detail{Metadata: map[string]string{"k": "v"}})
	_, raw, err := st.load("r1")
	if err != nil || !strings.Contains(string(raw), `"k":"v"`) {
		t.Fatalf("detail lost: err=%v raw=%s", err, raw)
	}
	if _, bytes, _ := st.usage(); bytes != 0 {
		t.Fatalf("failed write still counted %d disk bytes", bytes)
	}
}

// 详情写成功、摘要写失败：详情文件确实占着磁盘，必须计入用量。
func TestPartialDiskWriteIsStillCounted(t *testing.T) {
	dir := t.TempDir()
	st := openStore(dir, 10, 1<<30)
	started := time.Now()
	name := fmt.Sprintf("%013d-%s", started.UnixMilli(), "r1")
	if err := os.Mkdir(filepath.Join(dir, "records", name+".sum.json"), 0o700); err != nil { // rename 到目录上必然失败
		t.Fatal(err)
	}
	st.save(&summary{ID: "r1", StartedAt: started}, &detail{Metadata: map[string]string{"k": "v"}})
	info, err := os.Stat(filepath.Join(dir, "records", name+".body.json.gz"))
	if err != nil {
		t.Fatalf("detail file should have been written: %v", err)
	}
	if _, bytes, _ := st.usage(); bytes != info.Size() {
		t.Fatalf("disk usage = %d, want %d (the detail file)", bytes, info.Size())
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "records", "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("failed write left temp files behind: %v", leftovers)
	}
	if _, raw, _ := st.load("r1"); !strings.Contains(string(raw), `"k":"v"`) {
		t.Fatalf("detail lost: %s", raw)
	}
}
