package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type config struct {
	CaptureUpstream bool   `yaml:"capture_upstream" json:"capture_upstream"`
	DataDir         string `yaml:"data_dir" json:"data_dir"`
	MaxRecords      int    `yaml:"max_records" json:"max_records"`
	MaxDiskMB       int    `yaml:"max_disk_mb" json:"max_disk_mb"`
	MaxBodyMB       int    `yaml:"max_body_mb" json:"max_body_mb"`
	LearnSamples    int    `yaml:"learn_samples" json:"learn_samples"`
	ScanSecrets     bool   `yaml:"scan_secrets" json:"scan_secrets"`
	// RewriteEnvEnabled 为 true 且 RewriteEnvTimezone 非空时，把 Codex 请求里 <environment_context>
	// 的时区与日期改写为该 IANA 时区；关闭开关可暂停改写而不必清空时区。
	RewriteEnvEnabled  bool   `yaml:"rewrite_env_enabled" json:"rewrite_env_enabled"`
	RewriteEnvTimezone string `yaml:"rewrite_env_timezone" json:"rewrite_env_timezone"`
}

func defaultConfig() config {
	return config{
		CaptureUpstream: true,
		DataDir:         "plugins-data/cpa-inspector",
		MaxRecords:      2000,
		MaxDiskMB:       1024,
		MaxBodyMB:       8,
		LearnSamples:    30,
		ScanSecrets:     true,
		// 默认开启：旧配置只写了 rewrite_env_timezone 时保持原有改写行为
		RewriteEnvEnabled: true,
	}
}

func parseConfig(raw []byte) (config, error) {
	cfg := defaultConfig()
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("parse plugin config: %w", err)
		}
	}
	cfg.DataDir = strings.TrimSpace(cfg.DataDir)
	if cfg.DataDir == "" {
		cfg.DataDir = defaultConfig().DataDir
	}
	cfg.MaxRecords = clampInt(cfg.MaxRecords, 50, 100000)
	cfg.MaxDiskMB = clampInt(cfg.MaxDiskMB, 16, 1<<20)
	cfg.MaxBodyMB = clampInt(cfg.MaxBodyMB, 1, 256)
	cfg.LearnSamples = clampInt(cfg.LearnSamples, 1, 100000)
	cfg.RewriteEnvTimezone = strings.TrimSpace(cfg.RewriteEnvTimezone)
	if cfg.RewriteEnvTimezone != "" {
		// 拒绝 Local：它取决于宿主进程的时区，与"改写成指定时区"的意图不符
		if _, err := time.LoadLocation(cfg.RewriteEnvTimezone); err != nil || cfg.RewriteEnvTimezone == "Local" {
			return cfg, fmt.Errorf("rewrite_env_timezone: unknown IANA time zone %q", cfg.RewriteEnvTimezone)
		}
	}
	return cfg, nil
}

// envRewriteZone 返回实际生效的改写时区；开关关闭或未配置时区时为空（不改写）。
func (c config) envRewriteZone() string {
	if !c.RewriteEnvEnabled {
		return ""
	}
	return c.RewriteEnvTimezone
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// normalizeRequest 是 response.normalize_before 的入参。流式场景下宿主每个分片都会
// 重复携带完整的 OriginalRequest/TranslatedRequest（可能数 MB），所以这两个字段保持
// base64 原文、按需解码：关联请求只用 OriginalB64 的指纹，TranslatedB64 每个请求只解一次。
type normalizeRequest struct {
	FromFormat    string
	ToFormat      string
	Model         string
	Stream        bool
	OriginalB64   []byte
	TranslatedB64 []byte
	Body          []byte
}

var (
	keyOriginal   = []byte(`"OriginalRequest":`)
	keyTranslated = []byte(`"TranslatedRequest":`)
	keyBody       = []byte(`"Body":`)
)

// parseNormalizeRequest 先走快速路径：依赖宿主 encoding/json 按结构体字段顺序输出
// （FromFormat, ToFormat, Model, Stream, OriginalRequest, TranslatedRequest, Body），
// 且 base64 字符串内不含引号，用 memchr 级别的扫描跳过大字段；布局不符时回退到标准解码。
func parseNormalizeRequest(raw []byte) (*normalizeRequest, bool) {
	if req, ok := parseNormalizeFast(raw); ok {
		return req, true
	}
	var slow struct {
		FromFormat, ToFormat, Model string
		Stream                      bool
		OriginalRequest             json.RawMessage
		TranslatedRequest           json.RawMessage
		Body                        []byte
	}
	if err := json.Unmarshal(raw, &slow); err != nil {
		return nil, false
	}
	return &normalizeRequest{
		FromFormat: slow.FromFormat, ToFormat: slow.ToFormat, Model: slow.Model, Stream: slow.Stream,
		OriginalB64: unquoteB64(slow.OriginalRequest), TranslatedB64: unquoteB64(slow.TranslatedRequest),
		Body: slow.Body,
	}, true
}

func parseNormalizeFast(raw []byte) (*normalizeRequest, bool) {
	iOrig := bytes.Index(raw, keyOriginal)
	if iOrig < 0 || iOrig > 4096 {
		return nil, false
	}
	var head struct {
		FromFormat, ToFormat, Model string
		Stream                      bool
	}
	headJSON := append(append([]byte{}, bytes.TrimRight(raw[:iOrig], ", \t\r\n")...), '}')
	if err := json.Unmarshal(headJSON, &head); err != nil {
		return nil, false
	}
	orig, next, ok := scanB64Value(raw, iOrig+len(keyOriginal))
	if !ok || !bytes.HasPrefix(raw[next:], append([]byte{','}, keyTranslated...)) {
		return nil, false
	}
	trans, next, ok := scanB64Value(raw, next+1+len(keyTranslated))
	if !ok || !bytes.HasPrefix(raw[next:], append([]byte{','}, keyBody...)) {
		return nil, false
	}
	bodyB64, next, ok := scanB64Value(raw, next+1+len(keyBody))
	if !ok || !bytes.Equal(bytes.TrimSpace(raw[next:]), []byte("}")) {
		return nil, false
	}
	body := make([]byte, base64.StdEncoding.DecodedLen(len(bodyB64)))
	n, err := base64.StdEncoding.Decode(body, bodyB64)
	if err != nil {
		return nil, false
	}
	return &normalizeRequest{
		FromFormat: head.FromFormat, ToFormat: head.ToFormat, Model: head.Model, Stream: head.Stream,
		OriginalB64: orig, TranslatedB64: trans, Body: body[:n],
	}, true
}

// scanB64Value 读取 pos 处的 JSON 值：null 或不含转义的字符串。返回字符串内容与值之后的位置。
func scanB64Value(raw []byte, pos int) (val []byte, next int, ok bool) {
	if pos >= len(raw) {
		return nil, 0, false
	}
	if bytes.HasPrefix(raw[pos:], []byte("null")) {
		return nil, pos + 4, true
	}
	if raw[pos] != '"' {
		return nil, 0, false
	}
	end := bytes.IndexByte(raw[pos+1:], '"')
	if end < 0 {
		return nil, 0, false
	}
	return raw[pos+1 : pos+1+end], pos + 2 + end, true
}

func unquoteB64(raw json.RawMessage) []byte {
	if len(raw) < 2 || raw[0] != '"' {
		return nil
	}
	return raw[1 : len(raw)-1]
}

func decodeB64(b64 []byte) []byte {
	if len(b64) == 0 {
		return nil
	}
	out := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(out, b64)
	if err != nil {
		return nil
	}
	return out[:n]
}
