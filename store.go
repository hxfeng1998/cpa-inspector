package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// store 负责持久化：
//   records/<unixms>-<id>.sum.json      请求摘要（小，启动时全量加载作为索引）
//   records/<unixms>-<id>.body.json.gz  请求详情（大，按需读取）
//   schema.json / findings.json         字段基线与聚合发现项
// 磁盘不可写时退化为纯内存模式（只保留最近若干条详情）。

const memDetailRing = 40

type storedSummary struct {
	summary
	file string // 不含扩展名的文件前缀
	size int64
}

type store struct {
	mu         sync.Mutex
	dir        string
	memOnly    bool
	maxRecords int
	maxBytes   int64
	list       []*storedSummary // 按开始时间升序
	byID       map[string]*storedSummary
	diskBytes  int64
	memDetails map[string][]byte
	memOrder   []string
}

func openStore(dir string, maxRecords int, maxBytes int64) *store {
	st := &store{dir: dir, maxRecords: maxRecords, maxBytes: maxBytes, byID: make(map[string]*storedSummary), memDetails: make(map[string][]byte)}
	if err := os.MkdirAll(filepath.Join(dir, "records"), 0o700); err != nil {
		logf("data dir %s unavailable, falling back to memory only: %v", dir, err)
		st.memOnly = true
		return st
	}
	st.loadIndex()
	return st
}

func (st *store) setLimits(maxRecords int, maxBytes int64) {
	st.mu.Lock()
	st.maxRecords, st.maxBytes = maxRecords, maxBytes
	st.pruneLocked()
	st.mu.Unlock()
}

func (st *store) count() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.list)
}

func (st *store) loadIndex() {
	entries, err := os.ReadDir(filepath.Join(st.dir, "records"))
	if err != nil {
		return
	}
	sizes := make(map[string]int64)
	for _, entry := range entries {
		name := entry.Name()
		prefix, _, ok := strings.Cut(name, ".")
		if !ok {
			continue
		}
		if info, err := entry.Info(); err == nil {
			sizes[prefix] += info.Size()
		}
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sum.json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(st.dir, "records", name))
		if err != nil {
			continue
		}
		item := &storedSummary{file: strings.TrimSuffix(name, ".sum.json")}
		if json.Unmarshal(raw, &item.summary) != nil || item.ID == "" {
			continue
		}
		if pruneDynamicFindings(&item.summary) {
			if fixed, err := json.Marshal(item.summary); err == nil {
				_ = writeFileAtomic(filepath.Join(st.dir, "records", name), fixed)
			}
		}
		item.size = sizes[item.file]
		st.list = append(st.list, item)
		st.byID[item.ID] = item
		st.diskBytes += item.size
	}
	sort.SliceStable(st.list, func(i, j int) bool { return st.list[i].StartedAt.Before(st.list[j].StartedAt) })
}

func (st *store) save(sum *summary, det *detail) {
	sumJSON, err := json.Marshal(sum)
	if err != nil {
		logf("encode summary %s: %v", sum.ID, err)
		return
	}
	detJSON, err := json.Marshal(det)
	if err != nil {
		logf("encode detail %s: %v", sum.ID, err)
		detJSON = []byte(`{}`)
	}
	item := &storedSummary{summary: *sum, file: fmt.Sprintf("%013d-%s", sum.StartedAt.UnixMilli(), safeName(sum.ID))}

	if !st.memOnly {
		var gz bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&gz, gzip.BestSpeed)
		_, _ = zw.Write(detJSON)
		_ = zw.Close()
		base := filepath.Join(st.dir, "records", item.file)
		errBody := writeFileAtomic(base+".body.json.gz", gz.Bytes())
		errSum := writeFileAtomic(base+".sum.json", sumJSON)
		if errBody != nil || errSum != nil {
			logf("persist %s failed: %v %v", sum.ID, errBody, errSum)
		}
		item.size = int64(gz.Len() + len(sumJSON))
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	if st.memOnly {
		st.memDetails[sum.ID] = detJSON
		st.memOrder = append(st.memOrder, sum.ID)
		for len(st.memOrder) > memDetailRing {
			delete(st.memDetails, st.memOrder[0])
			st.memOrder = st.memOrder[1:]
		}
	}
	st.list = append(st.list, item)
	st.byID[item.ID] = item
	st.diskBytes += item.size
	st.pruneLocked()
}

func (st *store) pruneLocked() {
	for len(st.list) > 0 && (len(st.list) > st.maxRecords || st.diskBytes > st.maxBytes) {
		oldest := st.list[0]
		st.list = st.list[1:]
		delete(st.byID, oldest.ID)
		st.diskBytes -= oldest.size
		if !st.memOnly {
			base := filepath.Join(st.dir, "records", oldest.file)
			_ = os.Remove(base + ".sum.json")
			_ = os.Remove(base + ".body.json.gz")
		}
	}
}

// summaries 返回按时间倒序的摘要副本。
func (st *store) summaries() []summary {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]summary, 0, len(st.list))
	for i := len(st.list) - 1; i >= 0; i-- {
		out = append(out, st.list[i].summary)
	}
	return out
}

func (st *store) load(id string) (*summary, json.RawMessage, error) {
	st.mu.Lock()
	item := st.byID[id]
	var mem []byte
	if item != nil {
		mem = st.memDetails[id]
	}
	st.mu.Unlock()
	if item == nil {
		return nil, nil, os.ErrNotExist
	}
	sum := item.summary
	if st.memOnly {
		if mem == nil {
			mem = []byte(`{}`)
		}
		return &sum, mem, nil
	}
	f, err := os.Open(filepath.Join(st.dir, "records", item.file+".body.json.gz"))
	if err != nil {
		return &sum, []byte(`{}`), nil
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return &sum, []byte(`{}`), nil
	}
	raw, err := io.ReadAll(zr)
	if err != nil || !json.Valid(raw) {
		return &sum, []byte(`{}`), nil
	}
	return &sum, raw, nil
}

// patchUsage 把迟到的 usage 补到已落盘的最近记录上。
func (st *store) patchUsage(requestedAt time.Time, model, alias string, info usageInfo, channel string) {
	st.mu.Lock()
	var target *storedSummary
	for i := len(st.list) - 1; i >= 0 && i >= len(st.list)-50; i-- {
		item := st.list[i]
		if item.Usage != nil || (model != item.Model && model != item.RequestedModel && alias != item.RequestedModel) {
			continue
		}
		diff := requestedAt.Sub(item.StartedAt)
		if diff > -5*time.Second && diff < 5*time.Second {
			target = item
			break
		}
	}
	if target == nil {
		st.mu.Unlock()
		return
	}
	info.Headers = nil
	target.Usage = &info
	if target.Provider == "" {
		target.Provider = info.Provider
	}
	if target.Channel == "" {
		target.Channel = channel
	}
	sumJSON, _ := json.Marshal(target.summary)
	path := filepath.Join(st.dir, "records", target.file+".sum.json")
	memOnly := st.memOnly
	st.mu.Unlock()
	if !memOnly && sumJSON != nil {
		_ = writeFileAtomic(path, sumJSON)
	}
}

func (st *store) clearRecords() {
	st.mu.Lock()
	defer st.mu.Unlock()
	saved := st.maxRecords
	st.maxRecords = 0
	st.pruneLocked()
	st.maxRecords = saved
	st.memDetails, st.memOrder = make(map[string][]byte), nil
}

func (st *store) usage() (records int, bytes int64, memOnly bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.list), st.diskBytes, st.memOnly
}

func (st *store) loadState(schema *schemaStore, findings *map[string]*aggFinding) {
	if st.memOnly {
		return
	}
	if raw, err := os.ReadFile(filepath.Join(st.dir, "schema.json")); err == nil {
		loaded := newSchemaStore()
		if json.Unmarshal(raw, loaded) == nil && loaded.Scopes != nil {
			if loaded.Models == nil {
				loaded.Models = make(map[string]time.Time)
			}
			for _, sc := range loaded.Scopes {
				if sc.Models == nil {
					sc.Models = make(map[string]int)
				}
				if sc.ModelRequests == nil {
					sc.ModelRequests = make(map[string]int)
				}
				if sc.Fields == nil {
					sc.Fields = make(map[string]*fieldStat)
				}
				for _, f := range sc.Fields {
					if f.Types == nil {
						f.Types = make(map[string]int)
					}
					if f.Models == nil {
						f.Models = make(map[string]int)
					}
				}
			}
			if n := loaded.migrateDynamicPaths(); n > 0 {
				logf("migrated %d schema fields that were expanded per random id", n)
			}
			*schema = *loaded
		}
	}
	if raw, err := os.ReadFile(filepath.Join(st.dir, "findings.json")); err == nil {
		loaded := make(map[string]*aggFinding)
		if json.Unmarshal(raw, &loaded) == nil {
			dropped := 0
			for key, f := range loaded { // 同上：按随机 ID 报出来的"新字段"不是真漂移
				if f.Category == catDrift && spuriousDrift(f.Rule, f.Path) {
					delete(loaded, key)
					dropped++
				}
			}
			if dropped > 0 {
				logf("dropped %d spurious drift findings (random-id keys / content-dependent paths)", dropped)
			}
			*findings = loaded
		}
	}
}

func (st *store) saveState(schemaJSON, findingsJSON []byte) {
	if st.memOnly {
		return
	}
	if schemaJSON != nil {
		if err := writeFileAtomic(filepath.Join(st.dir, "schema.json"), schemaJSON); err != nil {
			logf("persist schema: %v", err)
		}
	}
	if findingsJSON != nil {
		if err := writeFileAtomic(filepath.Join(st.dir, "findings.json"), findingsJSON); err != nil {
			logf("persist findings: %v", err)
		}
	}
}

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func safeName(id string) string {
	var sb strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		}
	}
	if sb.Len() == 0 {
		return "unknown"
	}
	return truncate(sb.String(), 64)
}

// pruneDynamicFindings 去掉摘要里"按随机 ID 报出的新字段"，并重算级别。返回是否有改动。
func pruneDynamicFindings(sum *summary) bool {
	kept := sum.Findings[:0:0]
	for _, f := range sum.Findings {
		if f.Category == catDrift && spuriousDrift(f.Rule, f.Path) {
			continue
		}
		kept = append(kept, f)
	}
	if len(kept) == len(sum.Findings) {
		return false
	}
	sum.Findings, sum.Severity, sum.SeverityCounts = kept, "", make(map[string]int)
	for _, f := range kept {
		sum.SeverityCounts[f.Severity]++
		if severityRank[f.Severity] > severityRank[sum.Severity] {
			sum.Severity = f.Severity
		}
	}
	return true
}
