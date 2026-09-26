package main

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed ui/index.html
var uiHTML []byte

const (
	apiBase      = "/v0/management/" + pluginID
	resourceBase = "/v0/resource/plugins/" + pluginID
)

// managementRoutes：界面外壳走 resource 路由（宿主不鉴权，所以它只是不含任何数据的静态页面），
// 所有数据接口走 /v0/management/ 路由，由宿主用管理密钥鉴权。
func managementRoutes() managementRegistration {
	route := func(method, path, desc string) managementRoute {
		return managementRoute{Method: method, Path: "/" + pluginID + path, Description: desc}
	}
	return managementRegistration{
		Routes: []managementRoute{
			route(http.MethodGet, "/overview", "Inspector overview"),
			route(http.MethodGet, "/records", "Captured request list"),
			route(http.MethodGet, "/record", "Captured request detail"),
			route(http.MethodGet, "/schema", "Observed field atlas"),
			route(http.MethodGet, "/findings", "Aggregated findings"),
			route(http.MethodPost, "/ack-finding", "Acknowledge a finding"),
			route(http.MethodPost, "/ack-field", "Accept a field into the baseline"),
			route(http.MethodPost, "/rebaseline", "Accept everything observed so far as baseline"),
			route(http.MethodPost, "/clear", "Clear stored data"),
			route(http.MethodPost, "/timezones", "Filter time zones usable by rewrite_env_timezone"),
		},
		Resources: []managementRoute{{Path: "/ui", Menu: "CPA Inspector", Description: "请求/响应抓取、字段漂移与渠道安全分析"}},
	}
}

func handleManagement(req managementRequest) managementResponse {
	path := strings.TrimRight(req.Path, "/")
	if path == resourceBase+"/ui" {
		return managementResponse{StatusCode: http.StatusOK, Body: uiHTML, Headers: http.Header{
			"Content-Type":            {"text/html; charset=utf-8"},
			"Cache-Control":           {"no-store"},
			"X-Content-Type-Options":  {"nosniff"},
			"Referrer-Policy":         {"no-referrer"},
			"Content-Security-Policy": {"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"},
		}}
	}
	ins := currentInspector()
	if ins == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "inspector not configured"})
	}
	switch strings.TrimPrefix(path, apiBase) {
	case "/overview":
		return jsonResponse(http.StatusOK, ins.apiOverview())
	case "/records":
		return jsonResponse(http.StatusOK, ins.apiRecords(req))
	case "/record":
		return ins.apiRecord(req.Query.Get("id"))
	case "/schema":
		return jsonResponse(http.StatusOK, ins.apiSchema())
	case "/findings":
		return jsonResponse(http.StatusOK, ins.apiFindings())
	case "/ack-finding":
		var body struct {
			Key   string `json:"key"`
			Acked bool   `json:"acked"`
		}
		_ = json.Unmarshal(req.Body, &body)
		return jsonResponse(http.StatusOK, map[string]bool{"ok": ins.ackFinding(body.Key, body.Acked)})
	case "/ack-field":
		var body struct {
			Scope string `json:"scope"`
			Path  string `json:"path"`
			Acked bool   `json:"acked"`
		}
		_ = json.Unmarshal(req.Body, &body)
		return jsonResponse(http.StatusOK, map[string]bool{"ok": ins.ackField(body.Scope, body.Path, body.Acked)})
	case "/rebaseline":
		ins.rebaseline()
		return jsonResponse(http.StatusOK, map[string]bool{"ok": true})
	case "/timezones":
		var body struct {
			Zones []string `json:"zones"`
		}
		_ = json.Unmarshal(req.Body, &body)
		return jsonResponse(http.StatusOK, map[string]any{"zones": rewriteZoneOptions(body.Zones, time.Now())})
	case "/clear":
		var body struct {
			Target string `json:"target"`
		}
		_ = json.Unmarshal(req.Body, &body)
		ins.clear(body.Target)
		return jsonResponse(http.StatusOK, map[string]bool{"ok": true})
	}
	return jsonResponse(http.StatusNotFound, map[string]string{"error": "unknown route"})
}

type zoneOption struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"` // 当前 UTC 偏移（秒）
}

// rewriteZoneOptions 从界面给出的候选（浏览器的 IANA 列表）里筛出插件能解析的时区。
// 设置页只允许选这些：写进 config.yaml 的时区若无法解析，插件重载会失败。
func rewriteZoneOptions(names []string, now time.Time) []zoneOption {
	if len(names) > 2000 {
		names = names[:2000]
	}
	out := make([]zoneOption, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if len(name) > 64 || seen[name] {
			continue
		}
		seen[name] = true
		if loc := loadRewriteZone(name); loc != nil {
			_, offset := now.In(loc).Zone()
			out = append(out, zoneOption{Name: name, Offset: offset})
		}
	}
	return out
}

func jsonResponse(status int, v any) managementResponse {
	raw, err := json.Marshal(v)
	if err != nil {
		status, raw = http.StatusInternalServerError, []byte(`{"error":"encode failed"}`)
	}
	return managementResponse{StatusCode: status, Body: raw, Headers: http.Header{
		"Content-Type":  {"application/json; charset=utf-8"},
		"Cache-Control": {"no-store"},
	}}
}

// ---------- overview ----------

type groupStat struct {
	Name           string         `json:"name"`
	Requests       int            `json:"requests"`
	Failed         int            `json:"failed"`
	LastSeen       time.Time      `json:"last_seen"`
	AvgTTFBMs      int64          `json:"avg_ttfb_ms"`
	InputTokens    int64          `json:"input_tokens"`
	OutputTokens   int64          `json:"output_tokens"`
	CacheLost      int64          `json:"cache_lost_tokens"`
	CacheLostCount int            `json:"cache_lost_count"`
	Severity       string         `json:"severity,omitempty"`
	Channels       []string       `json:"channels,omitempty"`
	Models         []string       `json:"models,omitempty"`
	ResponseModels []string       `json:"response_models,omitempty"`
	Provenance     []string       `json:"provenance,omitempty"`
	Formats        []string       `json:"formats,omitempty"`
	SeverityCounts map[string]int `json:"severity_counts,omitempty"`

	ttfbSum, ttfbN int64
	sets           map[string]map[string]bool
}

func (g *groupStat) add(set, value string) {
	if value == "" {
		return
	}
	if g.sets == nil {
		g.sets = make(map[string]map[string]bool)
	}
	if g.sets[set] == nil {
		g.sets[set] = make(map[string]bool)
	}
	g.sets[set][value] = true
}

func (g *groupStat) seal() {
	if g.ttfbN > 0 {
		g.AvgTTFBMs = g.ttfbSum / g.ttfbN
	}
	g.Channels, g.Models = sortedSet(g.sets["channel"]), sortedSet(g.sets["model"])
	g.ResponseModels, g.Provenance, g.Formats = sortedSet(g.sets["response_model"]), sortedSet(g.sets["provenance"]), sortedSet(g.sets["format"])
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type hourBucket struct {
	Hour     time.Time `json:"hour"`
	Requests int       `json:"requests"`
	Failed   int       `json:"failed"`
	Flagged  int       `json:"flagged"` // 带 warn 及以上发现项的请求数
}

func (ins *inspector) apiOverview() map[string]any {
	sums := ins.store.summaries()
	now := time.Now()
	startHour := now.Truncate(time.Hour).Add(-23 * time.Hour)
	hours := make([]hourBucket, 24)
	for i := range hours {
		hours[i].Hour = startHour.Add(time.Duration(i) * time.Hour)
	}
	models, channels := make(map[string]*groupStat), make(map[string]*groupStat)
	var failed, last24 int
	for i := range sums {
		s := &sums[i]
		isFailed := s.Outcome != "succeeded"
		if isFailed {
			failed++
		}
		if idx := int(s.StartedAt.Sub(startHour) / time.Hour); idx >= 0 && idx < 24 && !s.StartedAt.Before(startHour) {
			last24++
			hours[idx].Requests++
			if isFailed {
				hours[idx].Failed++
			}
			if severityRank[s.Severity] >= severityRank[sevWarn] {
				hours[idx].Flagged++
			}
		}
		model := firstNonEmpty(s.Model, s.RequestedModel, "(unknown)")
		channel := firstNonEmpty(s.Channel, s.Provider, "(unknown)")
		for _, pair := range []struct {
			m    map[string]*groupStat
			name string
		}{{models, model}, {channels, channel}} {
			g := pair.m[pair.name]
			if g == nil {
				g = &groupStat{Name: pair.name, SeverityCounts: make(map[string]int)}
				pair.m[pair.name] = g
			}
			g.Requests++
			if isFailed {
				g.Failed++
			}
			if s.StartedAt.After(g.LastSeen) {
				g.LastSeen = s.StartedAt
			}
			if s.TTFBMs > 0 {
				g.ttfbSum += s.TTFBMs
				g.ttfbN++
			}
			if s.Usage != nil {
				g.InputTokens += s.Usage.InputTokens + s.Usage.CacheRead + s.Usage.CacheCreation
				g.OutputTokens += s.Usage.OutputTokens
			}
			if s.Cache != nil {
				g.CacheLost += s.Cache.Lost
				g.CacheLostCount++
			}
			if severityRank[s.Severity] > severityRank[g.Severity] {
				g.Severity = s.Severity
			}
			for sev, n := range s.SeverityCounts {
				g.SeverityCounts[sev] += n
			}
			g.add("channel", channel)
			g.add("model", model)
			g.add("response_model", s.ResponseModel)
			g.add("provenance", s.Provenance)
			g.add("format", strings.Trim(s.SourceFormat+" → "+s.ToFormat, " →"))
		}
	}

	ins.mu.Lock()
	sevCounts := map[string]int{}
	open := []*aggFinding{}
	for _, f := range ins.findings {
		if f.Acked {
			continue
		}
		sevCounts[f.Severity]++
		copied := *f
		open = append(open, &copied)
	}
	fields, drifted := 0, 0
	for _, sc := range ins.schema.Scopes {
		fields += len(sc.Fields)
		for _, f := range sc.Fields {
			if !f.Baseline && !f.Acked {
				drifted++
			}
		}
	}
	inflight := len(ins.active)
	stats := ins.stats
	cfg := ins.cfg
	scopes := len(ins.schema.Scopes)
	ins.mu.Unlock()

	sortAgg(open)
	if len(open) > 5 {
		open = open[:5]
	}
	records, diskBytes, memOnly := ins.store.usage()
	return map[string]any{
		"version": pluginVersion, "now": now, "started_at": ins.started,
		"records": records, "records_24h": last24, "failed": failed, "inflight": inflight,
		"finding_counts": sevCounts, "top_findings": open,
		"scopes": scopes, "fields": fields, "drifted_fields": drifted,
		"hours": hours, "models": sealGroups(models), "channels": sealGroups(channels),
		"storage": map[string]any{"bytes": diskBytes, "memory_only": memOnly},
		"stats":   map[string]int64{"requests": stats.Requests, "upstream_chunks": stats.UpstreamChunks, "downstream_chunks": stats.DownstreamChunks, "orphan_chunks": stats.Orphans},
		"config":  cfg,
	}
}

func sealGroups(m map[string]*groupStat) []*groupStat {
	out := make([]*groupStat, 0, len(m))
	for _, g := range m {
		g.seal()
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { // 并列时按名称定序：同样的数据必须产出同样的 JSON（界面据此判断是否需要重绘）
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortAgg(list []*aggFinding) {
	sort.SliceStable(list, func(i, j int) bool {
		if ri, rj := severityRank[list[i].Severity], severityRank[list[j].Severity]; ri != rj {
			return ri > rj
		}
		if !list[i].LastSeen.Equal(list[j].LastSeen) {
			return list[i].LastSeen.After(list[j].LastSeen)
		}
		return list[i].Key < list[j].Key
	})
}

// ---------- records ----------

func (ins *inspector) apiRecords(req managementRequest) map[string]any {
	q := strings.ToLower(strings.TrimSpace(req.Query.Get("q")))
	model, channel, outcome := req.Query.Get("model"), req.Query.Get("channel"), req.Query.Get("outcome")
	minSeverity := severityRank[req.Query.Get("severity")]
	limit := clampInt(atoi(req.Query.Get("limit"), 100), 1, 500)
	offset := max(atoi(req.Query.Get("offset"), 0), 0)

	matched := []summary{} // 非 nil：空列表必须序列化为 []，而不是 null
	for _, s := range ins.store.summaries() {
		if model != "" && s.Model != model && s.RequestedModel != model {
			continue
		}
		if channel != "" && s.Channel != channel && s.Provider != channel {
			continue
		}
		if outcome == "failed" && s.Outcome == "succeeded" || outcome == "succeeded" && s.Outcome != "succeeded" {
			continue
		}
		if severityRank[s.Severity] < minSeverity {
			continue
		}
		if q != "" && !summaryMatches(&s, q) {
			continue
		}
		matched = append(matched, s)
	}
	total := len(matched)
	if offset > total {
		offset = total
	}
	page := matched[offset:min(offset+limit, total)]

	ins.mu.Lock()
	live := make([]summary, 0, len(ins.active))
	for _, rec := range ins.active {
		if !rec.completed {
			s := rec.sum
			s.Outcome = "inflight"
			s.Findings = append([]finding(nil), s.Findings...)
			live = append(live, s)
		}
	}
	ins.mu.Unlock()
	sort.Slice(live, func(i, j int) bool { return live[i].StartedAt.After(live[j].StartedAt) })
	return map[string]any{"total": total, "offset": offset, "records": page, "inflight": live}
}

func summaryMatches(s *summary, q string) bool {
	fields := []string{s.ID, s.TraceID, s.SessionID, s.Model, s.RequestedModel, s.ResponseModel, s.Channel, s.Provider, s.Path, s.Error, s.AuthID, s.StopReason, s.Provenance}
	fields = append(fields, s.ToolCalls...)
	for _, f := range s.Findings {
		fields = append(fields, f.Title, f.Evidence, f.Rule, f.Path)
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), q) {
			return true
		}
	}
	return false
}

func (ins *inspector) apiRecord(id string) managementResponse {
	sum, det, err := ins.store.load(id)
	if err != nil {
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "record not found (可能仍在进行中，或已被清理)"})
	}
	sumJSON, _ := json.Marshal(sum)
	body := make([]byte, 0, len(sumJSON)+len(det)+32)
	body = append(body, `{"summary":`...)
	body = append(body, sumJSON...)
	body = append(body, `,"detail":`...)
	body = append(body, det...)
	body = append(body, '}')
	return managementResponse{StatusCode: http.StatusOK, Body: body, Headers: http.Header{"Content-Type": {"application/json; charset=utf-8"}, "Cache-Control": {"no-store"}}}
}

// ---------- schema ----------

type fieldView struct {
	Path string `json:"path"`
	*fieldStat
}

type scopeView struct {
	Scope        string         `json:"scope"`
	Direction    string         `json:"direction"`
	Format       string         `json:"format"`
	Event        string         `json:"event,omitempty"`
	Observations int            `json:"observations"`
	Requests     int            `json:"requests"`
	Learning     bool           `json:"learning"`
	Models       map[string]int `json:"models"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	Fields       []fieldView    `json:"fields"`
}

func (ins *inspector) apiSchema() map[string]any {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	views := make([]scopeView, 0, len(ins.schema.Scopes))
	for name, sc := range ins.schema.Scopes {
		parts := strings.SplitN(name, "|", 3)
		for len(parts) < 3 {
			parts = append(parts, "")
		}
		view := scopeView{Scope: name, Direction: parts[0], Format: parts[1], Event: parts[2], Observations: sc.Observations,
			Requests: sc.Requests, Learning: sc.Requests <= ins.cfg.LearnSamples, Models: copyCounts(sc.Models), FirstSeen: sc.FirstSeen, LastSeen: sc.LastSeen}
		for path, f := range sc.Fields {
			copied := *f
			copied.Types, copied.Models = copyCounts(f.Types), copyCounts(f.Models)
			view.Fields = append(view.Fields, fieldView{Path: path, fieldStat: &copied})
		}
		sort.Slice(view.Fields, func(i, j int) bool { return view.Fields[i].Path < view.Fields[j].Path })
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Scope < views[j].Scope })
	models := make(map[string]time.Time, len(ins.schema.Models))
	for name, first := range ins.schema.Models { // 返回值在解锁后才序列化，不能把共享 map 交出去
		models[name] = first
	}
	return map[string]any{"scopes": views, "learn_samples": ins.cfg.LearnSamples, "models": models}
}

func copyCounts(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// ---------- findings ----------

func (ins *inspector) apiFindings() map[string]any {
	ins.mu.Lock()
	list := make([]*aggFinding, 0, len(ins.findings))
	for _, f := range ins.findings {
		copied := *f
		list = append(list, &copied)
	}
	ins.mu.Unlock()
	sortAgg(list)
	return map[string]any{"findings": list}
}

func (ins *inspector) ackFinding(key string, acked bool) bool {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	f := ins.findings[key]
	if f == nil {
		return false
	}
	f.Acked = acked
	ins.findDirty = true
	if f.Category == catDrift && f.Scope != "" { // 确认漂移发现项 = 接受该字段进入基线
		if sc := ins.schema.Scopes[f.Scope]; sc != nil {
			if field := sc.Fields[f.Path]; field != nil {
				field.Acked = acked
				ins.schema.dirty = true
			}
		}
	}
	return true
}

func (ins *inspector) ackField(scope, path string, acked bool) bool {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	sc := ins.schema.Scopes[scope]
	if sc == nil || sc.Fields[path] == nil {
		return false
	}
	sc.Fields[path].Acked = acked
	ins.schema.dirty = true
	for _, f := range ins.findings {
		if f.Category == catDrift && f.Scope == scope && f.Path == path {
			f.Acked = acked
			ins.findDirty = true
		}
	}
	return true
}

// rebaseline：把当前观测到的一切认定为正常——所有字段并入基线，所有漂移发现项标记为已确认。
func (ins *inspector) rebaseline() {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	for _, sc := range ins.schema.Scopes {
		for _, f := range sc.Fields {
			f.Baseline, f.Acked = true, false
		}
	}
	for _, f := range ins.findings {
		if f.Category == catDrift {
			f.Acked = true
		}
	}
	ins.schema.dirty, ins.findDirty = true, true
}

func (ins *inspector) clear(target string) {
	if target == "records" || target == "all" {
		ins.store.clearRecords()
	}
	ins.mu.Lock()
	if target == "findings" || target == "all" {
		ins.findings = make(map[string]*aggFinding)
		ins.findDirty = true
	}
	if target == "schema" || target == "all" {
		ins.schema = newSchemaStore()
		ins.schema.dirty = true
	}
	ins.mu.Unlock()
	ins.flushState()
}

func atoi(s string, fallback int) int {
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return fallback
}
