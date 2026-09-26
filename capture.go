package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	scopeClientRequest      = "client_request"
	scopeUpstreamRequest    = "upstream_request"
	scopeUpstreamResponse   = "upstream_response"
	scopeDownstreamResponse = "downstream_response"
	scopeUpstreamHeaders    = "upstream_headers"
	scopeUpstreamWS         = "upstream_ws"
	scopeFingerprint        = "upstream_fingerprint"

	finalizeGrace   = 2 * time.Second  // 等 usage.handle 等迟到事件
	abandonAfter    = 20 * time.Minute // 在途请求无任何活动多久后强制落盘
	flushInterval   = 5 * time.Second
	maxAggFindings  = 5000
	maxRecFindings  = 64
	maxStoredEvents = 20000
)

// storedEvent 是保存下来供界面查看的一个流事件。
type storedEvent struct {
	T    int64           `json:"t"` // 距请求开始的毫秒数
	Name string          `json:"name,omitempty"`
	JSON json.RawMessage `json:"json,omitempty"`
	Text string          `json:"text,omitempty"`
}

// capture 是一个方向（上游/下游）的响应抓取。
type capture struct {
	Stream    bool                `json:"stream"`
	Format    string              `json:"format,omitempty"`
	Chunks    int                 `json:"chunks"`
	Bytes     int                 `json:"bytes"`
	FirstMs   int64               `json:"first_ms"`
	LastMs    int64               `json:"last_ms"`
	Truncated bool                `json:"truncated,omitempty"`
	Events    []storedEvent       `json:"events,omitempty"`
	Document  *storedBody         `json:"document,omitempty"`
	Message   *message            `json:"message,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`

	parser sseParser
	stored int
}

type storedBody struct {
	Size      int             `json:"size"`
	Truncated bool            `json:"truncated,omitempty"`
	JSON      json.RawMessage `json:"json,omitempty"`
	Text      string          `json:"text,omitempty"`
}

type attempt struct {
	T        int64               `json:"t"`
	ToFormat string              `json:"to_format,omitempty"`
	Model    string              `json:"model,omitempty"`
	Headers  map[string][]string `json:"headers,omitempty"`
}

type usageInfo struct {
	Provider        string              `json:"provider,omitempty"`
	BaseURL         string              `json:"base_url,omitempty"`
	ExecutorType    string              `json:"executor_type,omitempty"`
	Model           string              `json:"model,omitempty"`
	Alias           string              `json:"alias,omitempty"`
	AuthID          string              `json:"auth_id,omitempty"`
	AuthIndex       string              `json:"auth_index,omitempty"`
	AuthType        string              `json:"auth_type,omitempty"`
	ReasoningEffort string              `json:"reasoning_effort,omitempty"`
	ServiceTier     string              `json:"service_tier,omitempty"`
	LatencyMs       int64               `json:"latency_ms"`
	TTFTMs          int64               `json:"ttft_ms"`
	Failed          bool                `json:"failed,omitempty"`
	FailureStatus   int                 `json:"failure_status,omitempty"`
	FailureBody     string              `json:"failure_body,omitempty"`
	InputTokens     int64               `json:"input_tokens"`
	OutputTokens    int64               `json:"output_tokens"`
	ReasoningTokens int64               `json:"reasoning_tokens"`
	CacheRead       int64               `json:"cache_read_tokens"`
	CacheCreation   int64               `json:"cache_creation_tokens"`
	TotalTokens     int64               `json:"total_tokens"`
	Headers         map[string][]string `json:"response_headers,omitempty"`
}

// summary 是请求列表里的一行，也是落盘的索引文件内容。
type summary struct {
	ID             string         `json:"id"`
	TraceID        string         `json:"trace_id,omitempty"`
	StartedAt      time.Time      `json:"started_at"`
	CompletedAt    time.Time      `json:"completed_at"`
	DurationMs     int64          `json:"duration_ms"`
	Path           string         `json:"path,omitempty"`
	SourceFormat   string         `json:"source_format,omitempty"`
	ToFormat       string         `json:"to_format,omitempty"`
	RequestedModel string         `json:"requested_model,omitempty"`
	Model          string         `json:"model,omitempty"`
	ResponseModel  string         `json:"response_model,omitempty"`
	Stream         bool           `json:"stream"`
	Outcome        string         `json:"outcome"`
	StatusCode     int            `json:"status_code"`
	Error          string         `json:"error,omitempty"`
	Provider       string         `json:"provider,omitempty"`
	Channel        string         `json:"channel,omitempty"`
	AuthID         string         `json:"auth_id,omitempty"`
	Provenance     string         `json:"provenance,omitempty"`
	StopReason     string         `json:"stop_reason,omitempty"`
	Attempts       int            `json:"attempts"`
	RequestBytes   int            `json:"request_bytes"`
	UpstreamBytes  int            `json:"upstream_bytes"`
	DownBytes      int            `json:"downstream_bytes"`
	TTFBMs         int64          `json:"ttfb_ms"`
	Usage          *usageInfo     `json:"usage,omitempty"`
	ToolCalls      []string       `json:"tool_calls,omitempty"`
	Findings       []finding      `json:"findings,omitempty"`
	Severity       string         `json:"severity,omitempty"`
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`
	SessionID      string         `json:"session_id,omitempty"`
	Cache          *cacheVerdict  `json:"cache,omitempty"` // 非空表示本轮发生了本可避免的缓存失效
}

// detail 是落盘的请求详情（体积大，按需读取）。
type detail struct {
	ClientRequest   *storedBody         `json:"client_request,omitempty"`
	UpstreamRequest *storedBody         `json:"upstream_request,omitempty"`
	Upstream        *capture            `json:"upstream_response,omitempty"`
	Downstream      *capture            `json:"downstream_response,omitempty"`
	ClientHeaders   map[string][]string `json:"client_headers,omitempty"`
	Attempts        []attempt           `json:"attempts,omitempty"`
	Usages          []usageInfo         `json:"usages,omitempty"`
	Metadata        map[string]string   `json:"metadata,omitempty"`
	Rewrites        []string            `json:"rewrites,omitempty"` // 本插件对请求体做的改写（rewrite_env_timezone）
}

// record 是一个在途请求的全部状态。
type record struct {
	sum         summary
	det         detail
	clientBody  []byte
	sentBody    []byte // 本插件改写后交给宿主的请求体；nil 表示未改写
	upBody      []byte
	upBodySize  int
	upFormat    string
	wsUp        *capture // 上游 WebSocket 事件（Codex websockets 执行器）
	prints      []string
	findingKeys map[string]bool
	lastActive  time.Time
	completed   bool
	finalizeAt  time.Time
}

type inspector struct {
	mu        sync.Mutex
	flushMu   sync.Mutex // 串行化状态落盘：快照与写文件必须成对、按序完成
	cfg       config
	active    map[string]*record
	byPrint   map[string][]string
	pending   []*record
	schema    *schemaStore
	findings  map[string]*aggFinding
	findDirty bool
	store     *store
	sessions  *sessionTracker
	env       *envRewriter
	started   time.Time
	stats     struct{ Requests, UpstreamChunks, DownstreamChunks, Orphans int64 }
	stop      chan struct{}
	done      chan struct{}
}

var (
	globalMu sync.Mutex
	global   *inspector
)

func currentInspector() *inspector {
	globalMu.Lock()
	defer globalMu.Unlock()
	return global
}

// configureInspector 在 plugin.register / plugin.reconfigure 时调用。重配置保留内存状态。
func configureInspector(cfg config) {
	globalMu.Lock()
	defer globalMu.Unlock()
	if global != nil {
		global.mu.Lock()
		dirChanged := global.cfg.DataDir != cfg.DataDir
		global.cfg = cfg
		global.mu.Unlock()
		global.env.configure(cfg.envRewriteZone(), cfg.DataDir)
		if !dirChanged {
			global.store.setLimits(cfg.MaxRecords, int64(cfg.MaxDiskMB)<<20)
			return
		}
		global.shutdown()
	}
	env := newEnvRewriter()
	if global != nil {
		env = global.env // configure 按目标时区和数据目录隔离状态
	}
	env.configure(cfg.envRewriteZone(), cfg.DataDir)
	ins := &inspector{
		cfg:      cfg,
		active:   make(map[string]*record),
		byPrint:  make(map[string][]string),
		schema:   newSchemaStore(),
		findings: make(map[string]*aggFinding),
		store:    openStore(cfg.DataDir, cfg.MaxRecords, int64(cfg.MaxDiskMB)<<20),
		sessions: newSessionTracker(),
		env:      env,
		started:  time.Now(),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	ins.store.loadState(ins.schema, &ins.findings)
	ins.findDirty = true // 迁移可能清掉了旧发现项：下一次落盘时写回
	go ins.loop()
	global = ins
	logf("ready: data_dir=%s capture_upstream=%v rewrite_env_enabled=%v rewrite_env_timezone=%q records=%d", cfg.DataDir, cfg.CaptureUpstream, cfg.RewriteEnvEnabled, cfg.RewriteEnvTimezone, ins.store.count())
}

func flushInspector() {
	if ins := currentInspector(); ins != nil {
		ins.finalizeDue(true)
		ins.flushState()
	}
}

func shutdownInspector() {
	globalMu.Lock()
	ins := global
	global = nil
	globalMu.Unlock()
	if ins != nil {
		ins.shutdown()
	}
}

func (ins *inspector) shutdown() {
	select {
	case <-ins.stop:
		return
	default:
		close(ins.stop)
	}
	<-ins.done
	ins.finalizeDue(true)
	ins.flushState()
}

func (ins *inspector) loop() {
	defer close(ins.done)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	lastFlush := time.Now()
	for {
		select {
		case <-ins.stop:
			return
		case now := <-tick.C:
			ins.finalizeDue(false)
			if now.Sub(lastFlush) >= flushInterval {
				ins.flushState()
				lastFlush = now
			}
		}
	}
}

func (ins *inspector) flushState() {
	ins.flushMu.Lock()
	defer ins.flushMu.Unlock()
	ins.mu.Lock()
	var schemaJSON, findingsJSON []byte
	if ins.schema.dirty {
		schemaJSON, _ = json.Marshal(ins.schema)
		ins.schema.dirty = false
	}
	if ins.findDirty {
		findingsJSON, _ = json.Marshal(ins.findings)
		ins.findDirty = false
	}
	ins.mu.Unlock()
	schemaOK, findingsOK := ins.store.saveState(schemaJSON, findingsJSON)
	if !schemaOK || !findingsOK { // 写盘失败：恢复待写标记，下个周期重试
		ins.mu.Lock()
		ins.schema.dirty = ins.schema.dirty || !schemaOK
		ins.findDirty = ins.findDirty || !findingsOK
		ins.mu.Unlock()
	}
}

// ---------- 请求指纹：response.normalize_before 不带 RequestID，靠原始请求体指纹关联 ----------

const printHead, printTail = 64, 96

// fingerprintB64 取 base64 文本的 长度+头+尾 作指纹，不解码、不全量哈希。
func fingerprintB64(b64 []byte) string {
	if len(b64) == 0 {
		return ""
	}
	if len(b64) <= printHead+printTail {
		return strconv.Itoa(len(b64)) + ":" + string(b64)
	}
	return strconv.Itoa(len(b64)) + ":" + string(b64[:printHead]) + string(b64[len(b64)-printTail:])
}

// fingerprintBody 对原始字节算出与 fingerprintB64(base64(body)) 完全相同的指纹，只编码头尾。
func fingerprintBody(body []byte) string {
	n := len(body)
	if n == 0 {
		return ""
	}
	enc := base64.StdEncoding
	total := enc.EncodedLen(n)
	if total <= printHead+printTail {
		return strconv.Itoa(total) + ":" + enc.EncodeToString(body)
	}
	tailStart := 3*((n+2)/3) - printTail/4*3
	return strconv.Itoa(total) + ":" + enc.EncodeToString(body[:printHead/4*3]) + enc.EncodeToString(body[tailStart:])
}

// b64Equal 判断 b64 是否恰为 raw 的标准 base64 编码：分段编码后逐段比较，不分配整份副本。
func b64Equal(b64, raw []byte) bool {
	enc := base64.StdEncoding
	if len(raw) == 0 || len(b64) != enc.EncodedLen(len(raw)) {
		return false
	}
	var buf [4096]byte
	const step = len(buf) / 4 * 3
	for off := 0; off < len(raw); off += step {
		part := raw[off:min(off+step, len(raw))]
		n := enc.EncodedLen(len(part))
		enc.Encode(buf[:n], part)
		if !bytes.Equal(buf[:n], b64[off/3*4:off/3*4+n]) {
			return false
		}
	}
	return true
}

func (ins *inspector) addPrint(rec *record, body []byte) {
	fp := fingerprintBody(body)
	if fp == "" {
		return
	}
	for _, existing := range rec.prints {
		if existing == fp {
			return
		}
	}
	rec.prints = append(rec.prints, fp)
	ins.byPrint[fp] = append(ins.byPrint[fp], rec.sum.ID)
}

func (ins *inspector) dropPrints(rec *record) {
	for _, fp := range rec.prints {
		ids := ins.byPrint[fp]
		kept := ids[:0]
		for _, id := range ids {
			if id != rec.sum.ID {
				kept = append(kept, id)
			}
		}
		if len(kept) == 0 {
			delete(ins.byPrint, fp)
		} else {
			ins.byPrint[fp] = kept
		}
	}
}

// matchUpstream 为一个无 RequestID 的上游分片找到所属请求。
func (ins *inspector) matchUpstream(req *normalizeRequest) *record {
	if ids := ins.byPrint[fingerprintB64(req.OriginalB64)]; len(ids) > 0 {
		var live []*record
		for i := len(ids) - 1; i >= 0; i-- {
			if rec := ins.active[ids[i]]; rec != nil && !rec.completed {
				live = append(live, rec)
			}
		}
		// 指纹只取长度+首尾，中段不同的等长请求会撞上：多个在途候选时再比对完整请求体。
		// 只在有歧义时付出这份开销；请求体完全相同（或都对不上）时仍取最新的在途请求。
		if len(live) > 1 {
			for _, rec := range live {
				if b64Equal(req.OriginalB64, rec.clientBody) || (rec.sentBody != nil && b64Equal(req.OriginalB64, rec.sentBody)) {
					return rec
				}
			}
		}
		if len(live) > 0 {
			return live[0]
		}
		if rec := ins.active[ids[len(ids)-1]]; rec != nil {
			return rec
		}
	}
	var candidate *record
	for _, rec := range ins.active { // 兜底：指纹对不上（请求体被别的插件改写）时，按模型找唯一在途请求
		if rec.completed || (rec.sum.Model != req.Model && rec.sum.RequestedModel != req.Model) {
			continue
		}
		if candidate != nil {
			return nil
		}
		candidate = rec
	}
	return candidate
}

// ---------- 钩子处理 ----------

func (ins *inspector) ensure(id string, now time.Time) *record {
	rec := ins.active[id]
	if rec == nil {
		rec = &record{findingKeys: make(map[string]bool)}
		rec.sum.ID = id
		rec.sum.StartedAt = now
		ins.active[id] = rec
		ins.stats.Requests++
	}
	rec.lastActive = now
	return rec
}

func (ins *inspector) onRequest(req *requestInterceptRequest, afterAuth bool) {
	if req.RequestID == "" {
		return
	}
	now := time.Now()
	ins.mu.Lock()
	defer ins.mu.Unlock()
	rec := ins.ensure(req.RequestID, now)
	s := &rec.sum
	s.TraceID, s.SourceFormat, s.Stream = req.TraceID, req.SourceFormat, req.Stream
	if req.RequestedModel != "" {
		s.RequestedModel = req.RequestedModel
	}
	if s.Model == "" || afterAuth {
		s.Model = req.Model
	}
	ins.absorbMetadata(rec, req.Metadata)
	// 选定凭据后宿主传来的是本插件改写过的请求体：客户端原文保持不变
	if len(req.Body) > 0 && !bytes.Equal(req.Body, rec.clientBody) && !(afterAuth && rec.sentBody != nil && bytes.Equal(req.Body, rec.sentBody)) {
		rec.clientBody = req.Body
		s.RequestBytes = len(req.Body)
		ins.addPrint(rec, req.Body)
	}
	if !afterAuth {
		rec.det.ClientHeaders = redactHeaders(req.Headers)
		return
	}
	s.ToFormat = req.ToFormat
	s.Attempts++
	if s.Attempts > 1 {
		// 新一次尝试：上一次尝试的上游请求体与响应重组状态作废，否则最终分析会拿新响应去比旧请求、
		// 把两次尝试的流混在一起。上一次的失败信息仍保留在 usages 与 attempts 里。
		rec.upBody, rec.upBodySize, rec.upFormat = nil, 0, ""
		rec.det.Upstream, rec.wsUp = nil, nil
	}
	if len(rec.det.Attempts) < 16 {
		rec.det.Attempts = append(rec.det.Attempts, attempt{T: now.Sub(s.StartedAt).Milliseconds(), ToFormat: req.ToFormat, Model: req.Model, Headers: redactHeaders(req.Headers)})
	}
}

// onRewrittenRequest 记录一次 request.intercept_before：客户端原文照常抓取，另记下改写后的请求体。
// 宿主会把改写结果同时当作 OriginalRequest 传给 normalize_before，所以两份都要登记指纹。
func (ins *inspector) onRewrittenRequest(req *requestInterceptRequest, sent []byte, notes []string) {
	ins.onRequest(req, false)
	if req.RequestID == "" {
		return
	}
	ins.mu.Lock()
	defer ins.mu.Unlock()
	rec := ins.active[req.RequestID]
	if rec == nil {
		return
	}
	rec.sentBody = sent
	rec.det.Rewrites = notes
	ins.addPrint(rec, sent)
}

func (ins *inspector) absorbMetadata(rec *record, meta map[string]any) {
	for _, key := range []string{"request_path", "selected_auth_id", "selected_auth_index", "execution_session_id", "canonical_session_id", "reasoning_effort", "service_tier", "caller_scope"} {
		v, ok := meta[key]
		if !ok || v == nil {
			continue
		}
		text := strings.TrimSpace(fmt.Sprint(v))
		if text == "" || len(text) > 256 {
			continue
		}
		if rec.det.Metadata == nil {
			rec.det.Metadata = make(map[string]string)
		}
		rec.det.Metadata[key] = text
	}
	if p := rec.det.Metadata["request_path"]; p != "" {
		rec.sum.Path = p
	}
	if a := rec.det.Metadata["selected_auth_id"]; a != "" && rec.sum.AuthID == "" {
		rec.sum.AuthID = a
	}
}

func (ins *inspector) onUpstreamChunk(req *normalizeRequest) {
	now := time.Now()
	ins.mu.Lock()
	defer ins.mu.Unlock()
	ins.stats.UpstreamChunks++
	rec := ins.matchUpstream(req)
	if rec == nil {
		// 找不到所属请求：仍然把形态并入字段图谱（漂移检测不依赖关联）。
		ins.stats.Orphans++
		orphan := &capture{Stream: req.Stream}
		ins.absorb(nil, orphan, scopeUpstreamResponse, req.FromFormat, req.Model, req.Body, req.Stream, now)
		return
	}
	rec.lastActive = now
	if rec.det.Upstream == nil {
		rec.det.Upstream = &capture{Stream: req.Stream, Message: newMessage()}
	}
	if rec.upBody == nil && len(req.TranslatedB64) > 0 {
		rec.upBody = decodeB64(req.TranslatedB64)
		rec.upBodySize = len(rec.upBody)
		rec.upFormat = req.FromFormat
	}
	ins.absorb(rec, rec.det.Upstream, scopeUpstreamResponse, req.FromFormat, req.Model, req.Body, req.Stream, now)
}

func (ins *inspector) onDownstreamChunk(req *streamChunkInterceptRequest) {
	if req.RequestID == "" {
		return
	}
	now := time.Now()
	ins.mu.Lock()
	defer ins.mu.Unlock()
	rec := ins.ensure(req.RequestID, now)
	ins.fillIdentity(rec, req.SourceFormat, req.Model, req.RequestedModel, true)
	ins.absorbMetadata(rec, req.Metadata)
	if rec.det.Downstream == nil {
		rec.det.Downstream = &capture{Stream: true, Message: newMessage()}
	}
	if len(req.ResponseHeaders) > 0 && rec.det.Downstream.Headers == nil {
		rec.det.Downstream.Headers = redactHeaders(req.ResponseHeaders)
	}
	if req.ChunkIndex < 0 { // 仅头部的初始化调用
		if rec.clientBody == nil && len(req.OriginalRequest) > 0 {
			rec.clientBody = req.OriginalRequest
			rec.sum.RequestBytes = len(req.OriginalRequest)
			ins.addPrint(rec, req.OriginalRequest)
		}
		return
	}
	ins.stats.DownstreamChunks++
	ins.absorb(rec, rec.det.Downstream, scopeDownstreamResponse, req.SourceFormat, rec.schemaModel(), req.Body, true, now)
}

func (ins *inspector) onDownstreamResponse(req *responseInterceptRequest) {
	if req.RequestID == "" {
		return
	}
	now := time.Now()
	ins.mu.Lock()
	defer ins.mu.Unlock()
	rec := ins.ensure(req.RequestID, now)
	ins.fillIdentity(rec, req.SourceFormat, req.Model, req.RequestedModel, false)
	ins.absorbMetadata(rec, req.Metadata)
	if rec.clientBody == nil && len(req.OriginalRequest) > 0 {
		rec.clientBody = req.OriginalRequest
		rec.sum.RequestBytes = len(req.OriginalRequest)
	}
	rec.det.Downstream = &capture{Stream: false, Message: newMessage(), Headers: redactHeaders(req.ResponseHeaders)}
	ins.absorb(rec, rec.det.Downstream, scopeDownstreamResponse, req.SourceFormat, rec.schemaModel(), req.Body, false, now)
}

func (ins *inspector) onWebSocketEvent(ev *webSocketResponseEvent) {
	if ev.RequestID == "" {
		return
	}
	now := time.Now()
	ins.mu.Lock()
	defer ins.mu.Unlock()
	rec := ins.ensure(ev.RequestID, now)
	if ev.Provider != "" {
		rec.sum.Provider = ev.Provider
	}
	if ev.AuthID != "" {
		rec.sum.AuthID = ev.AuthID
	}
	// WebSocket 上游事件单独抓取、单独建基线（scope 方向为 upstream_ws）：
	// 同协议直通时 response.normalize_before 不触发，这是拿到上游原文的唯一途径；
	// 翻译路由下两边都有数据，收尾时以 normalize_before 的为准。
	if rec.wsUp == nil {
		rec.wsUp = &capture{Stream: true, Message: newMessage()}
	}
	payload := ev.Payload
	if ev.EventType != "" && !bytes.Contains(payload, []byte(`"type"`)) {
		payload = append([]byte("event: "+ev.EventType+"\n"), payload...)
	}
	ins.absorb(rec, rec.wsUp, scopeUpstreamWS, "codex", rec.schemaModel(), payload, true, now)
}

func (ins *inspector) fillIdentity(rec *record, sourceFormat, model, requestedModel string, stream bool) {
	s := &rec.sum
	if s.SourceFormat == "" {
		s.SourceFormat = sourceFormat
	}
	if s.Model == "" {
		s.Model = model
	}
	if s.RequestedModel == "" {
		s.RequestedModel = requestedModel
	}
	if stream {
		s.Stream = true
	}
}

func (rec *record) schemaModel() string {
	if rec.sum.Model != "" {
		return rec.sum.Model
	}
	return rec.sum.RequestedModel
}

// absorb 处理一个方向上的一段载荷：计数、保存、重组、并入字段图谱。rec 为 nil 表示孤儿分片。
func (ins *inspector) absorb(rec *record, c *capture, direction, hostFormat, model string, body []byte, stream bool, now time.Time) {
	var offset int64
	reqID := ""
	if rec != nil {
		offset = now.Sub(rec.sum.StartedAt).Milliseconds()
		reqID = rec.sum.ID
	}
	if c.Chunks == 0 {
		c.FirstMs = offset
	}
	c.Chunks++
	c.Bytes += len(body)
	c.LastMs = offset
	budget := ins.cfg.MaxBodyMB << 20

	if !stream {
		doc, ok := decodeJSON(body)
		if rec != nil {
			c.Document = makeStoredBody(body, budget)
		}
		if !ok {
			return
		}
		if c.Message != nil {
			c.Message.feedDocument(doc)
			c.Format = c.Message.Format
		}
		ins.observeShape(rec, direction, routeLabel(rec, direction, formatLabel(c.Format, hostFormat)), "(document)", model, reqID, doc, now)
		return
	}

	if c.Message != nil && c.Bytes > budget*reassembleFactor {
		c.Message.Overflow = true
	}
	for _, ev := range c.parser.parse(body) {
		if c.Message != nil && !c.Message.Overflow {
			c.Message.feed(ev)
			c.Format = c.Message.Format
		}
		if rec != nil {
			if c.stored+len(ev.Data) <= budget && len(c.Events) < maxStoredEvents {
				se := storedEvent{T: offset, Name: ev.Name}
				if ev.JSON != nil {
					se.JSON = ev.Data
				} else {
					se.Text = string(ev.Data)
				}
				c.Events = append(c.Events, se)
				c.stored += len(ev.Data)
			} else {
				c.Truncated = true
			}
		}
		if ev.JSON == nil {
			continue
		}
		name := ev.Name
		if name == "" {
			name = "(data)"
		}
		ins.observeShape(rec, direction, routeLabel(rec, direction, formatLabel(c.Format, hostFormat)), name, model, reqID, ev.JSON, now)
	}
}

func formatLabel(detected, hostFormat string) string {
	if detected != "" && detected != fmtUnknown {
		return detected
	}
	if hostFormat != "" {
		return hostFormat
	}
	return fmtUnknown
}

// routeLabel：下游响应若经过协议翻译，形态取决于"翻译自哪种上游协议"，与直通的原生响应分开建基线。
func routeLabel(rec *record, direction, format string) string {
	if rec == nil || direction != scopeDownstreamResponse {
		return format
	}
	if to := rec.sum.ToFormat; to != "" && to != rec.sum.SourceFormat {
		return format + "←" + to
	}
	return format
}

func scopeKey(direction, format, event string) string {
	if event == "" {
		return direction + "|" + format
	}
	return direction + "|" + format + "|" + event
}

// observeShape 把一份 JSON 并入字段图谱，并把漂移事件转成发现项。调用方需持锁。
func (ins *inspector) observeShape(rec *record, direction, format, event, model, reqID string, doc any, now time.Time) {
	scope := scopeKey(direction, format, event)
	events := ins.schema.observe(scope, model, reqID, extractShape(doc), ins.cfg.LearnSamples, now)
	for _, ev := range events {
		ins.report(rec, driftFinding(ev, ins.baseFinding(rec, now)))
	}
}

func (ins *inspector) baseFinding(rec *record, now time.Time) finding {
	f := finding{Time: now}
	if rec != nil {
		f.RequestID, f.Model, f.Channel = rec.sum.ID, rec.schemaModel(), rec.sum.Channel
	}
	return f
}

// report 记录一条发现项：挂到请求上，并并入全局聚合。调用方需持锁。
func (ins *inspector) report(rec *record, f finding) {
	if f.Key == "" {
		f.Key = findingKey(f.Rule, f.Title, f.Evidence)
	}
	f.Evidence = maskSecretsIn(f.Evidence) // 在算完 Key 之后：打码不应改变聚合键
	if rec != nil && !rec.findingKeys[f.Key] && len(rec.sum.Findings) < maxRecFindings {
		rec.findingKeys[f.Key] = true
		rec.sum.Findings = append(rec.sum.Findings, f)
	}
	agg := ins.findings[f.Key]
	if agg == nil {
		if len(ins.findings) >= maxAggFindings {
			ins.evictFindings()
		}
		agg = &aggFinding{finding: f, FirstSeen: f.Time, FirstReq: f.RequestID}
		ins.findings[f.Key] = agg
	}
	agg.Count++
	agg.Severity, agg.Title, agg.Detail = f.Severity, f.Title, f.Detail // 以最新一次为准：规则调整后旧聚合项随之更新
	agg.LastSeen = f.Time
	agg.RequestID = f.RequestID
	if f.Channel != "" {
		agg.Channel = f.Channel
	}
	ins.findDirty = true
}

// evictFindings 聚合表满时淘汰最久未出现的低级别条目。
func (ins *inspector) evictFindings() {
	list := make([]*aggFinding, 0, len(ins.findings))
	for _, f := range ins.findings {
		list = append(list, f)
	}
	sort.Slice(list, func(i, j int) bool {
		if ri, rj := severityRank[list[i].Severity], severityRank[list[j].Severity]; ri != rj {
			return ri < rj
		}
		return list[i].LastSeen.Before(list[j].LastSeen)
	})
	for _, f := range list[:len(list)/10+1] {
		delete(ins.findings, f.Key)
	}
}

func (ins *inspector) onComplete(done *requestCompletion) {
	now := time.Now()
	ins.mu.Lock()
	defer ins.mu.Unlock()
	rec := ins.active[done.RequestID]
	if rec == nil || rec.completed {
		return
	}
	s := &rec.sum
	ins.fillIdentity(rec, done.SourceFormat, done.Model, done.RequestedModel, done.Stream)
	s.Outcome, s.StatusCode, s.Error = done.Outcome, done.StatusCode, truncate(done.Error, 4096)
	if !done.StartedAt.IsZero() {
		s.StartedAt = done.StartedAt
	}
	s.CompletedAt = done.CompletedAt
	if s.CompletedAt.IsZero() {
		s.CompletedAt = now
	}
	rec.completed = true
	rec.finalizeAt = now.Add(finalizeGrace)
	ins.pending = append(ins.pending, rec)
}

func (ins *inspector) onUsage(u *usageRecord) {
	info := usageInfo{
		Provider: u.Provider, BaseURL: u.BaseURL, ExecutorType: u.ExecutorType, Model: u.Model, Alias: u.Alias,
		AuthID: u.AuthID, AuthIndex: u.AuthIndex, AuthType: u.AuthType, ReasoningEffort: u.ReasoningEffort, ServiceTier: u.ServiceTier,
		LatencyMs: u.Latency.Milliseconds(), TTFTMs: u.TTFT.Milliseconds(),
		Failed: u.Failed, FailureStatus: u.Failure.StatusCode, FailureBody: truncate(u.Failure.Body, 16<<10),
		InputTokens: u.Detail.InputTokens, OutputTokens: u.Detail.OutputTokens, ReasoningTokens: u.Detail.ReasoningTokens,
		CacheRead: u.Detail.CacheReadTokens, CacheCreation: u.Detail.CacheCreationTokens, TotalTokens: u.Detail.TotalTokens,
		Headers: redactHeaders(u.ResponseHeaders),
	}
	if info.CacheRead == 0 {
		info.CacheRead = u.Detail.CachedTokens
	}
	now := time.Now()
	ins.mu.Lock()
	rec := ins.matchUsage(u)
	if rec != nil {
		ins.attachUsage(rec, info, now)
	}
	ins.observeHeaders(rec, u, now)
	ins.mu.Unlock()
	if rec == nil {
		// 请求已落盘（usage 迟到超过宽限期）：补写到已保存的记录上。
		ins.store.patchUsage(u.RequestedAt, u.Model, u.Alias, info, channelOf(info))
	}
}

// matchUsage：usage.handle 同样不带 RequestID，按"模型一致 + 开始时间最接近"关联。
func (ins *inspector) matchUsage(u *usageRecord) *record {
	var best *record
	bestDiff := 5 * time.Second
	for _, rec := range ins.active {
		s := &rec.sum
		if u.Model != s.Model && u.Model != s.RequestedModel && (u.Alias == "" || u.Alias != s.RequestedModel) {
			continue
		}
		diff := u.RequestedAt.Sub(s.StartedAt)
		if diff < 0 {
			diff = -diff
		}
		if rec.completed && !u.RequestedAt.IsZero() && u.RequestedAt.After(s.CompletedAt.Add(time.Second)) {
			continue
		}
		if len(rec.det.Usages) > 0 && !rec.det.Usages[len(rec.det.Usages)-1].Failed {
			diff += 2 * time.Second // 已有成功 usage 的请求优先级靠后
		}
		if diff < bestDiff {
			best, bestDiff = rec, diff
		}
	}
	return best
}

func (ins *inspector) attachUsage(rec *record, info usageInfo, now time.Time) {
	rec.lastActive = now
	if len(rec.det.Usages) < 16 {
		rec.det.Usages = append(rec.det.Usages, info)
	}
	s := &rec.sum
	if s.Usage == nil || !info.Failed {
		copied := info
		copied.Headers, copied.FailureBody = nil, truncate(info.FailureBody, 512)
		s.Usage = &copied
	}
	if info.Provider != "" {
		s.Provider = info.Provider
	}
	if info.AuthID != "" {
		s.AuthID = info.AuthID
	}
	if ch := channelOf(info); ch != "" {
		s.Channel = ch
	}
	if f := checkBaseURL(info.BaseURL, ins.baseFinding(rec, now)); f != nil {
		ins.report(rec, *f)
	}
}

// observeHeaders 把上游响应头名并入字段图谱（新的响应头也是灰测/换后端的信号）。
func (ins *inspector) observeHeaders(rec *record, u *usageRecord, now time.Time) {
	if len(u.ResponseHeaders) == 0 {
		return
	}
	entries := make([]shapeEntry, 0, len(u.ResponseHeaders))
	for name, values := range u.ResponseHeaders {
		example := ""
		if len(values) > 0 && !isSensitiveHeader(name) {
			example = truncate(values[0], 96)
		}
		entries = append(entries, shapeEntry{Path: strings.ToLower(name), Type: "header", Example: example})
	}
	reqID := ""
	if rec != nil {
		reqID = rec.sum.ID
	}
	scope := scopeKey(scopeUpstreamHeaders, channelOf(usageInfo{BaseURL: u.BaseURL, Provider: u.Provider}), "")
	for _, ev := range ins.schema.observe(scope, u.Model, reqID, entries, ins.cfg.LearnSamples, now) {
		ins.report(rec, driftFinding(ev, ins.baseFinding(rec, now)))
	}
}

// channelOf 返回渠道标识：优先上游 host，其次 provider。
func channelOf(info usageInfo) string {
	if info.BaseURL != "" {
		if u, err := url.Parse(info.BaseURL); err == nil && u.Host != "" {
			return u.Host
		}
	}
	return info.Provider
}

func makeStoredBody(body []byte, budget int) *storedBody {
	if body == nil {
		return nil
	}
	sb := &storedBody{Size: len(body)}
	if len(body) > budget {
		sb.Truncated = true
		sb.Text = truncate(string(body[:budget]), budget)
		return sb
	}
	if json.Valid(body) {
		sb.JSON = body
	} else {
		sb.Text = string(body)
	}
	return sb
}
