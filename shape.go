package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// 字段形态（shape）提取：把任意 JSON 展开成 "路径 → 类型" 的集合。
//   - 数组折叠为 []；数组元素若带字符串 type/role 判别字段，则写成 []<判别值>；
//     嵌套对象带 type 时同样写成 key<判别值>。这样新的内容块类型会以新路径出现，
//     且不同变体的字段互不混淆。
//   - 判别/枚举类字段（type、stop_reason…）的取值记为伪路径 "path=value"，用于发现新枚举值。
//   - 用户数据驱动的子树（工具入参、JSON Schema 等）视为不透明，不再下钻，避免路径爆炸。

const (
	shapeMaxDepth = 14
	shapeMaxPaths = 1500
	shapeMaxKeys  = 64
)

var opaqueKeys = map[string]bool{
	"input_schema": true, "parameters": true, "input": true, "arguments": true, "args": true,
	"properties": true, "schema": true, "json_schema": true, "parametersJsonSchema": true,
	"responseJsonSchema": true, "responseSchema": true, "structuredContent": true, "partial_json": true,
}

var enumKeys = map[string]bool{
	"type": true, "stop_reason": true, "finish_reason": true, "finishReason": true, "role": true,
	"object": true, "status": true, "service_tier": true, "event": true, "reason": true,
	"blockReason": true, "phase": true,
}

var enumValuePattern = regexp.MustCompile(`^[A-Za-z0-9_.:\-/]{1,48}$`)

type shapeEntry struct {
	Path    string
	Type    string
	Example string
}

func extractShape(v any) []shapeEntry {
	w := &shapeWalker{seen: make(map[string]int)}
	w.walk(v, "", 0)
	return w.out
}

type shapeWalker struct {
	out  []shapeEntry
	seen map[string]int // path|type → out 下标
}

func (w *shapeWalker) add(path, typ, example string) {
	if path == "" {
		path = "$"
	}
	key := path + "|" + typ
	if _, ok := w.seen[key]; ok || len(w.out) >= shapeMaxPaths {
		return
	}
	w.seen[key] = len(w.out)
	w.out = append(w.out, shapeEntry{Path: path, Type: typ, Example: example})
}

func (w *shapeWalker) walk(v any, path string, depth int) {
	switch t := v.(type) {
	case nil:
		w.add(path, "null", "null")
	case bool:
		w.add(path, "bool", strconv.FormatBool(t))
	case json.Number:
		w.add(path, "number", t.String())
	case float64:
		w.add(path, "number", strconv.FormatFloat(t, 'g', -1, 64))
	case string:
		w.add(path, "string", truncate(t, 96))
	case []any:
		w.add(path, "array", "["+strconv.Itoa(len(t))+"]")
		if depth >= shapeMaxDepth {
			return
		}
		for _, item := range t {
			w.walk(item, path+"[]"+discriminator(item), depth+1)
		}
	case map[string]any:
		w.add(path, "object", "{"+strconv.Itoa(len(t))+"}")
		if depth >= shapeMaxDepth {
			return
		}
		if len(t) > shapeMaxKeys {
			w.add(path+".*", "dynamic", "{"+strconv.Itoa(len(t))+" keys}")
			return
		}
		for key, child := range t {
			segment := collapseDynamicKey(key)
			childPath := segment
			if path != "" {
				childPath = path + "." + segment
			}
			if opaqueKeys[key] {
				w.add(childPath, "opaque:"+jsonKind(child), "")
				continue
			}
			if s, ok := child.(string); ok && enumKeys[key] && enumValuePattern.MatchString(s) {
				w.add(childPath+"="+s, "enum", s)
			}
			// 多态对象（content_block、delta…）按 type 分路径，否则不同变体的字段会互相"缺失"。
			w.walk(child, childPath+typeDiscriminator(child), depth+1)
		}
	}
}

// 动态键：有些对象是"以 ID 为键的映射"（如 usage.attribution.items.rs_0e24…），键每次请求都不同。
// 把它们当字段会让每个请求都冒出一批"新字段"。这里把 ID 形态的键折叠成通配，并保留有语义的前缀：
// rs_0e24489f… → {rs_*}，at_098dab76-fe15-… → {at_*}，纯数字 → {#}。
var (
	dynUUID  = regexp.MustCompile(`^([A-Za-z]{1,8}[_-])?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	dynHex   = regexp.MustCompile(`^([A-Za-z]{1,8}[_-])?[0-9a-fA-F]{16,}$`)
	dynToken = regexp.MustCompile(`^([A-Za-z]{1,8}[_-])[A-Za-z0-9]{20,}$`)
	dynDigit = regexp.MustCompile(`^[0-9]+$`)
)

func collapseDynamicKey(key string) string {
	if len(key) < 1 || len(key) > 200 {
		return key
	}
	if dynDigit.MatchString(key) {
		return "{#}"
	}
	for _, re := range []*regexp.Regexp{dynUUID, dynHex, dynToken} {
		m := re.FindStringSubmatch(key)
		if m == nil {
			continue
		}
		if re == dynToken && countDigits(key[len(m[1]):]) < 2 { // 纯字母的长单词不是 ID
			continue
		}
		return "{" + m[1] + "*}"
	}
	return key
}

func countDigits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

// normalizePath 把一条已落盘的路径按当前的动态键规则重新折叠（用于迁移旧数据）。
func normalizePath(path string) string {
	segments := strings.Split(path, ".")
	for i, seg := range segments {
		cut := strings.IndexAny(seg, "[<=")
		if cut < 0 {
			cut = len(seg)
		}
		segments[i] = collapseDynamicKey(seg[:cut]) + seg[cut:]
	}
	return strings.Join(segments, ".")
}

// migrateDynamicPaths 把旧基线里按随机 ID 展开的字段并入折叠后的路径，返回被合并的条数。
func (s *schemaStore) migrateDynamicPaths() int {
	merged := 0
	for _, sc := range s.Scopes {
		for path, f := range sc.Fields {
			norm := normalizePath(path)
			if norm == path {
				continue
			}
			merged++
			delete(sc.Fields, path)
			dst := sc.Fields[norm]
			if dst == nil {
				f.Baseline, f.Acked = true, false // 这些本就不是漂移，直接视为基线
				sc.Fields[norm] = f
				continue
			}
			dst.Baseline = true
			dst.Count = min(sc.Observations, dst.Count+f.Count)
			for typ, n := range f.Types {
				dst.Types[typ] += n
			}
			for model, n := range f.Models {
				dst.Models[model] = min(sc.Models[model], dst.Models[model]+n)
			}
			if f.FirstSeen.Before(dst.FirstSeen) {
				dst.FirstSeen, dst.FirstReqID = f.FirstSeen, f.FirstReqID
			}
			if f.LastSeen.After(dst.LastSeen) {
				dst.LastSeen, dst.LastReqID = f.LastSeen, f.LastReqID
			}
		}
	}
	if merged > 0 {
		s.dirty = true
	}
	return merged
}

func discriminator(item any) string {
	obj, ok := item.(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"type", "role"} {
		if s, ok := obj[key].(string); ok && enumValuePattern.MatchString(s) {
			return "<" + s + ">"
		}
	}
	return ""
}

// typeDiscriminator 只认 type（role 仅用于数组元素），供非数组的嵌套对象使用。
func typeDiscriminator(item any) string {
	if obj, ok := item.(map[string]any); ok {
		if s, ok := obj["type"].(string); ok && enumValuePattern.MatchString(s) {
			return "<" + s + ">"
		}
	}
	return ""
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case json.Number, float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && cut < len(s) && s[cut]&0xC0 == 0x80 { // 不切断 UTF-8 多字节序列
		cut--
	}
	return s[:cut] + "…"
}

// ---------- 字段图谱（schema store）与漂移检测 ----------

type fieldStat struct {
	Types      map[string]int `json:"types"`
	Count      int            `json:"count"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
	FirstReqID string         `json:"first_request_id,omitempty"`
	LastReqID  string         `json:"last_request_id,omitempty"`
	Example    string         `json:"example,omitempty"`
	Models     map[string]int `json:"models"`
	// Baseline 为 true 表示该字段在学习期内出现，属于基线；false 表示学习期之后才出现（漂移）。
	Baseline bool `json:"baseline"`
	Acked    bool `json:"acked,omitempty"`
}

type scopeStat struct {
	Observations int            `json:"observations"` // 文档/事件数：出现率的分母
	Requests     int            `json:"requests"`     // 请求数：学习期按它计（一个流有上百个事件）
	Models       map[string]int `json:"models"`
	// ModelRequests 为各模型贡献的请求数，用作"该模型是否已观测充分"的门槛。
	ModelRequests map[string]int `json:"model_requests"`
	lastReqID     string
	Fields        map[string]*fieldStat `json:"fields"`
	FirstSeen     time.Time             `json:"first_seen"`
	LastSeen      time.Time             `json:"last_seen"`
}

type schemaStore struct {
	Scopes map[string]*scopeStat `json:"scopes"`
	Models map[string]time.Time  `json:"models"` // 见过的模型 → 首次出现时间
	dirty  bool
}

func newSchemaStore() *schemaStore {
	return &schemaStore{Scopes: make(map[string]*scopeStat), Models: make(map[string]time.Time)}
}

type driftEvent struct {
	Kind    string // new_field | new_enum | new_field_for_model | missing_field | type_change
	Scope   string
	Path    string
	Type    string
	Example string
	Model   string
	Prior   string
}

// observe 把一份文档的形态并入 scope，返回相对基线的漂移事件。调用方需持有 inspector 锁。
//
// 判定规则（learn 为学习样本数）：
//   - scope 的前 learn 个请求：一切并入基线，不报。
//   - 之后出现的全新路径 → new_field（枚举伪路径 → new_enum）。同一次观测里若祖先路径也是新的，
//     只报祖先（例如新内容块类型只报 content[]<x> 一条，而不是它的每个子字段）。
//   - 路径已存在、在其它模型里近乎必现（≥90%），而该模型已有 > learn 个请求从未带过、现在带上了
//     → new_field_for_model。这正是"某个模型悄悄进入灰测、开始返回别的模型才有的字段"的信号。
//   - 该模型此前近乎必现（≥95%）的非数组字段这次缺失 → missing_field（渠道切换后端的典型信号）。
//   - 已有路径出现新的 JSON 类型 → type_change。
func (s *schemaStore) observe(scope, model, reqID string, entries []shapeEntry, learn int, now time.Time) []driftEvent {
	if len(entries) == 0 {
		return nil
	}
	s.dirty = true
	var events []driftEvent
	sc := s.Scopes[scope]
	if sc == nil {
		sc = &scopeStat{Models: make(map[string]int), ModelRequests: make(map[string]int), Fields: make(map[string]*fieldStat), FirstSeen: now}
		s.Scopes[scope] = sc
	}
	if reqID == "" || reqID != sc.lastReqID {
		sc.lastReqID = reqID
		sc.Requests++
		if model != "" {
			sc.ModelRequests[model]++
		}
	}
	learning := sc.Requests <= learn
	modelSeen := sc.Models[model]
	othersObs := sc.Observations - modelSeen
	modelMature := sc.ModelRequests[model] > learn
	othersMature := sc.Requests-sc.ModelRequests[model] >= learn
	checkMissing := !strings.HasPrefix(scope, "client_request") && !strings.HasPrefix(scope, "upstream_request")
	counted := make(map[string]bool, len(entries))
	newPaths := make(map[string]bool)

	for _, e := range entries {
		f := sc.Fields[e.Path]
		if f == nil {
			f = &fieldStat{Types: make(map[string]int), Models: make(map[string]int), FirstSeen: now, FirstReqID: reqID, Baseline: learning, Example: e.Example}
			sc.Fields[e.Path] = f
			if !learning {
				newPaths[e.Path] = true
				kind := "new_field"
				if e.Type == "enum" {
					kind = "new_enum"
				}
				events = append(events, driftEvent{Kind: kind, Scope: scope, Path: e.Path, Type: e.Type, Example: e.Example, Model: model})
			}
		} else if !counted[e.Path] || f.Types[e.Type] == 0 {
			if f.Types[e.Type] == 0 && !learning && !newPaths[e.Path] && e.Type != "null" && !onlyNull(f.Types) {
				events = append(events, driftEvent{Kind: "type_change", Scope: scope, Path: e.Path, Type: e.Type, Example: e.Example, Model: model, Prior: joinKeys(f.Types)})
			}
			if model != "" && !counted[e.Path] && f.Models[model] == 0 && modelMature && othersMature && othersObs > 0 && !strings.Contains(e.Path, "{") {
				if othersCount := f.Count - f.Models[model]; float64(othersCount) >= 0.9*float64(othersObs) {
					events = append(events, driftEvent{Kind: "new_field_for_model", Scope: scope, Path: e.Path, Type: e.Type, Example: e.Example, Model: model})
				}
			}
		}
		f.Types[e.Type]++
		if !counted[e.Path] {
			counted[e.Path] = true
			f.Count++
			if model != "" {
				f.Models[model]++
			}
		}
		f.LastSeen = now
		f.LastReqID = reqID
		if e.Example != "" && (f.Example == "" || e.Type == "enum") {
			f.Example = e.Example
		}
	}

	if model != "" && modelMature && checkMissing && modelSeen > 0 {
		for path, f := range sc.Fields {
			if counted[path] || contentDependent(path) || strings.Contains(path, "=") {
				continue
			}
			if float64(f.Models[model]) >= 0.95*float64(modelSeen) {
				events = append(events, driftEvent{Kind: "missing_field", Scope: scope, Path: path, Type: joinKeys(f.Types), Example: f.Example, Model: model})
			}
		}
	}

	sc.Observations++
	sc.LastSeen = now
	if model != "" {
		sc.Models[model]++
	}
	return collapseDrift(events, newPaths)
}

// contentDependent 报告路径是否取决于对话内容：数组元素（content[]…）与以 ID 为键的映射条目（items.{ctco_*}…）。
// 它们出现与否由对话里有没有对应的块 / 工具调用决定，不能拿"出现率"判断缺失。
func contentDependent(path string) bool {
	return strings.Contains(path, "[]") || strings.Contains(path, "{")
}

// spuriousDrift 识别旧版本产生的、现在看来不成立的漂移发现项（用于启动时清理）：
// 按随机 ID 展开的"新字段"，以及对内容相关路径报的"必现字段缺失 / 某模型新增字段"。
func spuriousDrift(rule, path string) bool {
	if normalizePath(path) != path {
		return true
	}
	return (rule == "missing_field" || rule == "new_field_for_model") && contentDependent(path)
}

// collapseDrift 丢弃"祖先路径在同一次观测里也是新路径"的 new_field/new_enum 事件。
func collapseDrift(events []driftEvent, newPaths map[string]bool) []driftEvent {
	if len(newPaths) < 2 {
		return events
	}
	out := events[:0]
	for _, ev := range events {
		if (ev.Kind == "new_field" || ev.Kind == "new_enum") && hasNewAncestor(ev.Path, newPaths) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func hasNewAncestor(path string, newPaths map[string]bool) bool {
	for i := len(path) - 1; i > 0; i-- {
		if c := path[i]; (c == '.' || c == '=' || c == '[') && newPaths[path[:i]] {
			return true
		}
	}
	return false
}

// observeModel 记录模型名，首次出现时返回 true。
func (s *schemaStore) observeModel(model string, now time.Time) bool {
	if model == "" {
		return false
	}
	if _, ok := s.Models[model]; ok {
		return false
	}
	s.Models[model] = now
	s.dirty = true
	return true
}

func onlyNull(types map[string]int) bool {
	for t := range types {
		if t != "null" {
			return false
		}
	}
	return true
}

func joinKeys(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
}

// decodeJSON 以 UseNumber 解码，保留大整数精度。
func decodeJSON(raw []byte) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}
