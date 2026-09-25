package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// 磁盘仅保存摘要与日期，不保存会话 ID、环境原文或凭据。内存淘汰不删除磁盘映射。
// 这些状态不属于抓包记录，不能随 max_records / max_disk_mb 清理，否则历史会重新换算。
type envSession struct {
	Version int               `json:"version"`
	Known   bool              `json:"known"`
	Pins    map[string]string `json:"pins"`
}

func envHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func envSessionKey(headers http.Header, doc, host map[string]any) string {
	value := func(m map[string]any, key string) string {
		s, _ := m[key].(string)
		return strings.TrimSpace(s)
	}
	header := func(names ...string) string {
		for _, want := range names {
			for k, vs := range headers {
				if strings.EqualFold(k, want) && len(vs) > 0 && strings.TrimSpace(vs[0]) != "" {
					return strings.TrimSpace(vs[0])
				}
			}
		}
		return ""
	}
	client, _ := doc["client_metadata"].(map[string]any)
	// 线程 ID 优先，避免多个子线程共用父 session_id 的映射；不截断任何 ID。
	identity := ""
	for _, candidate := range []string{
		value(client, "thread_id"), value(doc, "thread_id"), header("thread-id", "x-thread-id"),
		value(host, "canonical_session_id"),
		value(client, "session_id"), header("session-id", "session_id", "x-session-id"),
		value(doc, "session_id"), value(doc, "conversation_id"), header("conversation-id", "conversation_id", "x-conversation-id"),
		value(host, "execution_session_id"), value(doc, "prompt_cache_key"),
	} {
		if candidate != "" {
			identity = candidate
			break
		}
	}
	if identity == "" {
		identity, _ = doc["conversation"].(string)
		if conversation, ok := doc["conversation"].(map[string]any); ok {
			identity = value(conversation, "id")
		}
	}
	if identity == "" {
		return ""
	}
	// 宿主提供调用方作用域时一并隔离，避免不同调用方复用相同的会话 ID。
	parts, _ := json.Marshal([]string{value(host, "caller_scope"), identity})
	return envHash(string(parts))
}

func (r *envRewriter) sessionPath(key string) string {
	return filepath.Join(r.dir, "env-timezone", "v1", envHash(r.zone), key+".json")
}

// 调用方持有 r.mu；只缓存已有状态，不缓存任意陌生请求。
func (r *envRewriter) loadSession(key string) (*envSession, error) {
	empty := func() *envSession { return &envSession{Version: 1, Pins: make(map[string]string)} }
	if key == "" {
		return empty(), nil
	}
	if state := r.sessions[key]; state != nil {
		return state, nil
	}
	if r.dir == "" {
		return empty(), nil
	}
	raw, err := os.ReadFile(r.sessionPath(key))
	if os.IsNotExist(err) {
		return empty(), nil
	}
	if err != nil {
		return nil, err
	}
	var state envSession
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, err
	}
	if state.Version != 1 || state.Pins == nil {
		return nil, fmt.Errorf("invalid environment rewrite state")
	}
	for hash, date := range state.Pins {
		if decoded, err := hex.DecodeString(hash); err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid environment pin key")
		}
		if date != "" && date != "-" {
			if _, err := time.Parse(dateLayout, date); err != nil {
				return nil, err
			}
		}
	}
	r.cacheSession(key, &state)
	return &state, nil
}

func (r *envRewriter) cacheSession(key string, state *envSession) {
	if len(r.sessions) >= 1024 {
		r.sessions = make(map[string]*envSession)
	}
	r.sessions[key] = state
}

func (r *envRewriter) saveSession(key string, state *envSession) error {
	// 无持久化目录时仅用于单元测试；生产初始化始终传入 data_dir。
	if r.dir != "" {
		path := r.sessionPath(key)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
		raw, err := json.Marshal(state)
		if err != nil {
			return err
		}
		if err := writeEnvState(path, raw); err != nil {
			return err
		}
	}
	r.cacheSession(key, state)
	return nil
}

// 在返回改写结果之前同步保存；异常退出不会只留下一个尚未落盘的首次映射。
func writeEnvState(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".env-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
