package main

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 请求收尾：重活（整份请求体的 JSON 解码、形态提取、机密扫描）都放在这里，
// 由后台协程在请求结束后执行，不占用代理转发的热路径。

// finalizeDue 收尾所有到期的请求。force 为 true 时（关停/静默）不等宽限期，连在途请求一并落盘。
func (ins *inspector) finalizeDue(force bool) {
	now := time.Now()
	ins.mu.Lock()
	var due []*record
	kept := ins.pending[:0]
	for _, rec := range ins.pending {
		if force || !now.Before(rec.finalizeAt) {
			due = append(due, rec)
		} else {
			kept = append(kept, rec)
		}
	}
	ins.pending = kept
	for id, rec := range ins.active {
		if rec.completed {
			continue
		}
		if force || now.Sub(rec.lastActive) > abandonAfter {
			rec.completed = true
			rec.sum.Outcome = "abandoned"
			rec.sum.CompletedAt = rec.lastActive
			due = append(due, rec)
			_ = id
		}
	}
	for _, rec := range due {
		delete(ins.active, rec.sum.ID)
		ins.dropPrints(rec)
	}
	cfg := ins.cfg
	ins.mu.Unlock()

	for _, rec := range due {
		ins.finalize(rec, cfg)
	}
}

func (ins *inspector) finalize(rec *record, cfg config) {
	s := &rec.sum
	now := time.Now()
	if s.CompletedAt.IsZero() {
		s.CompletedAt = now
	}
	s.DurationMs = s.CompletedAt.Sub(s.StartedAt).Milliseconds()
	succeeded := s.Outcome == "succeeded"
	budget := cfg.MaxBodyMB << 20

	// 1) 无锁阶段：解码、提取、跑规则。
	clientDoc, clientOK := decodeJSON(rec.clientBody)
	upDoc, upOK := decodeJSON(rec.upBody)
	var clientShape, upShape []shapeEntry
	if clientOK {
		clientShape = extractShape(clientDoc)
	}
	if upOK {
		upShape = extractShape(upDoc)
	}
	rec.det.ClientRequest = makeStoredBody(rec.clientBody, budget)
	rec.det.UpstreamRequest = makeStoredBody(rec.upBody, budget)

	base := finding{Time: now, RequestID: s.ID, Model: rec.schemaModel(), Channel: s.Channel}
	var found []finding
	if rec.det.Upstream == nil && rec.wsUp != nil && rec.wsUp.Chunks > 0 {
		rec.det.Upstream = rec.wsUp // 直通路由：WebSocket 事件就是上游原文
	}
	up, down := rec.det.Upstream, rec.det.Downstream

	if up != nil && up.Message != nil {
		m := up.Message
		m.finish(up.Stream, succeeded, true)
		s.ResponseModel, s.StopReason, s.UpstreamBytes = m.Model, m.StopReason, up.Bytes
		if m.Format == fmtClaude {
			s.Provenance = claudeProvenance(m.ID)
		}
		for _, issue := range m.Issues {
			found = append(found, integrityFinding(base, "上游", issue, sevWarn))
		}
		if f := checkModel(s.Model, m.Model, base); f != nil {
			found = append(found, *f)
		}
		found = append(found, checkClaudeFingerprint(m, base)...)
		if f := checkTokenInflation(m, rec.upBodySize, base); f != nil {
			found = append(found, *f)
		}
		found = append(found, checkToolCalls("上游响应", m, declaredTools(upDoc), upOK, base)...)
	}
	if down != nil && down.Message != nil {
		m := down.Message
		m.finish(down.Stream, succeeded, false)
		s.DownBytes, s.TTFBMs = down.Bytes, down.FirstMs
		if s.StopReason == "" {
			s.StopReason = m.StopReason
		}
		for _, call := range m.toolCalls() {
			if len(s.ToolCalls) < 12 {
				s.ToolCalls = append(s.ToolCalls, call.Name)
			}
		}
		for _, issue := range m.Issues {
			found = append(found, integrityFinding(base, "下游", issue, sevNotice))
		}
		found = append(found, checkToolCalls("下游响应", m, declaredTools(clientDoc), clientOK, base)...)
		found = append(found, checkNewDomains(m, rec.clientBody, base)...)
		if up == nil { // 未抓上游时，用下游响应兜底做渠道可信度检查
			if s.ResponseModel == "" {
				s.ResponseModel = m.Model
			}
			if f := checkModel(s.Model, m.Model, base); f != nil && checkModel(s.RequestedModel, m.Model, base) != nil {
				found = append(found, *f)
			}
			if s.ToFormat == s.SourceFormat { // 同协议直通：下游即上游原文，请求体也基本等于客户端请求体
				if isClaudeFormat(s.ToFormat) {
					found = append(found, checkClaudeFingerprint(m, base)...)
				}
				if f := checkTokenInflation(m, len(rec.clientBody), base); f != nil {
					found = append(found, *f)
				}
			}
		}
		if succeeded && len(m.Blocks) == 0 && m.Error == "" && !strings.Contains(s.Path, "count_tokens") {
			f := base
			f.Severity, f.Category, f.Rule = sevNotice, catIntegrity, "empty-response"
			f.Title = "请求成功但响应没有任何内容块"
			f.Key = findingKey(f.Rule, base.Model, base.Channel)
			found = append(found, f)
		}
	}
	// 宿主是否把上游响应头下发给客户端：界面据此如实标注"④ 返回客户端"的 Headers。
	passthrough := hostPassthroughHeaders()
	if rec.det.Metadata == nil {
		rec.det.Metadata = make(map[string]string)
	}
	rec.det.Metadata["host_passthrough_headers"] = passthrough
	if f := checkStickyHeaderDropped(rec, passthrough, base); f != nil {
		found = append(found, *f)
	}
	if cfg.ScanSecrets && len(rec.clientBody) > 0 {
		secrets := scanSecrets(rec.clientBody, base)
		if isOfficialChannel(s.Channel) {
			for i := range secrets {
				secrets[i].Severity = sevInfo
				secrets[i].Detail = "该内容会随对话上下文发给上游（本次为官方端点）。"
			}
		}
		found = append(found, secrets...)
	}

	// 2) 持锁阶段：并入字段图谱与聚合发现项。
	ins.mu.Lock()
	if clientShape != nil {
		ins.mergeShape(rec, scopeKey(scopeClientRequest, orUnknown(s.SourceFormat), ""), clientShape, now)
	}
	if upShape != nil {
		ins.mergeShape(rec, scopeKey(scopeUpstreamRequest, orUnknown(firstNonEmpty(rec.upFormat, s.ToFormat)), ""), upShape, now)
	}
	// 后端指纹按渠道建基线：用上游原文；同协议直通时下游即上游原文。
	var origin *message
	if up != nil {
		origin = up.Message
	} else if down != nil && s.ToFormat == s.SourceFormat {
		origin = down.Message
	}
	if entries := fingerprintEntries(origin); len(entries) > 0 && succeeded {
		ins.mergeShape(rec, scopeKey(scopeFingerprint, orUnknown(origin.Format), firstNonEmpty(s.Channel, s.Provider, "(unknown)")), entries, now)
	}
	if ins.schema.observeModel(rec.schemaModel(), now) && ins.store.count() >= cfg.LearnSamples {
		f := base
		f.Severity, f.Category, f.Rule = sevInfo, catDrift, "new-model"
		f.Title = "首次观测到该模型"
		f.Evidence = rec.schemaModel()
		f.Key = findingKey(f.Rule, rec.schemaModel())
		found = append(found, f)
	}
	for _, f := range found {
		ins.report(rec, f)
	}
	ins.mu.Unlock()

	sortFindings(s.Findings)
	s.SeverityCounts = make(map[string]int)
	for _, f := range s.Findings {
		s.SeverityCounts[f.Severity]++
		if severityRank[f.Severity] > severityRank[s.Severity] {
			s.Severity = f.Severity
		}
	}

	// 3) 无锁阶段：落盘。
	rec.clientBody, rec.upBody = nil, nil
	ins.store.save(&rec.sum, &rec.det)
}

func (ins *inspector) mergeShape(rec *record, scope string, shape []shapeEntry, now time.Time) {
	for _, ev := range ins.schema.observe(scope, rec.schemaModel(), rec.sum.ID, shape, ins.cfg.LearnSamples, now) {
		ins.report(rec, driftFinding(ev, ins.baseFinding(rec, now)))
	}
}

func integrityFinding(base finding, side, issue, severity string) finding {
	f := base
	f.Severity, f.Category, f.Rule = severity, catIntegrity, "stream-integrity"
	f.Title = side + "响应协议不完整"
	f.Evidence = issue
	f.Key = findingKey(f.Rule, side, issue, base.Model, base.Channel)
	return f
}

func isClaudeFormat(format string) bool {
	return strings.Contains(strings.ToLower(format), "claude")
}

var officialHosts = []string{
	"api.anthropic.com", "api.openai.com", "chatgpt.com", "googleapis.com", "api.x.ai", "api.moonshot.cn", "api.kimi.com",
}

func isOfficialChannel(channel string) bool {
	host := strings.ToLower(channel)
	if u, err := url.Parse("//" + host); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	for _, official := range officialHosts {
		if host == official || strings.HasSuffix(host, "."+official) {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return fmtUnknown
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// stickyResponseHeaders 是"上游下发、期望客户端在后续请求里原样带回"的响应头。
var stickyResponseHeaders = []string{"x-codex-turn-state"}

// checkStickyHeaderDropped：上游下发了需要客户端回传的头，但宿主没有开启响应头透传，
// 客户端收不到，也就不可能回传——这条链路在代理这一跳断了。
func checkStickyHeaderDropped(rec *record, passthrough string, base finding) *finding {
	if passthrough != passthroughOff || len(rec.det.Usages) == 0 {
		return nil
	}
	upstream := rec.det.Usages[len(rec.det.Usages)-1].Headers
	for _, name := range stickyResponseHeaders {
		if !hasHeader(upstream, name) || hasHeader(rec.det.ClientHeaders, name) {
			continue
		}
		f := base
		f.Severity, f.Category, f.Rule = sevNotice, catIntegrity, "sticky-header-dropped"
		f.Title = "上游下发了需回传的响应头，但 CPA 未透传给客户端"
		f.Detail = "CPA 的 passthrough-headers 为关闭（默认值），上游响应头不会下发给客户端，客户端也就无法在后续请求里带回它。对 X-Codex-Turn-State 而言，这可能让同一轮对话的后续请求失去上游的会话粘性（路由到不同后端、缓存命中下降）。在 config.yaml 里设置 passthrough-headers: true 即可。"
		f.Evidence = http.CanonicalHeaderKey(name)
		f.Key = findingKey(f.Rule, name, base.Channel)
		return &f
	}
	return nil
}

func hasHeader(headers map[string][]string, name string) bool {
	for key := range headers {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}
