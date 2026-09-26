package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime/debug"
	"time"
)

// 以下结构体镜像宿主 sdk/pluginapi 的 JSON 形态。宿主侧结构体没有 json tag，
// 因此字段名即 Go 字段名；[]byte 以 base64 字符串传输。
// 这里自行声明而不 import 宿主模块，避免把整个 CLIProxyAPI 依赖树拉进插件。

const (
	pluginID = "cpa-inspector"
	// schemaVersion 取 6：流式分片不再重复携带请求体/历史分片，management JSON 响应不做 HTML 转义。
	schemaVersion = 6
	pluginVersion = "0.1.11"
	repoURL       = "https://github.com/hxfeng1998/cpa-inspector"

	methodPluginRegister          = "plugin.register"
	methodPluginReconfigure       = "plugin.reconfigure"
	methodPluginQuiesce           = "plugin.quiesce"
	methodPluginShutdown          = "plugin.shutdown"
	methodRequestInterceptBefore  = "request.intercept_before"
	methodRequestInterceptAfter   = "request.intercept_after"
	methodRequestComplete         = "request.complete"
	methodResponseNormalizeBefore = "response.normalize_before"
	methodResponseInterceptAfter  = "response.intercept_after"
	methodResponseStreamChunk     = "response.intercept_stream_chunk"
	methodWebSocketResponseEvent  = "websocket.response_event"
	methodUsageHandle             = "usage.handle"
	methodManagementRegister      = "management.register"
	methodManagementHandle        = "management.handle"
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}

type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type lifecycleRequest struct {
	ConfigYAML    []byte `json:"config_yaml"`
	SchemaVersion uint32 `json:"schema_version"`
}

type pluginMetadata struct {
	Name             string
	Version          string
	Author           string
	GitHubRepository string
	Logo             string
	ConfigFields     []configField
}

type configField struct {
	Name        string
	Type        string
	EnumValues  []string
	Description string
}

type registration struct {
	SchemaVersion uint32         `json:"schema_version"`
	Metadata      pluginMetadata `json:"metadata"`
	Capabilities  capabilities   `json:"capabilities"`
}

type capabilities struct {
	RequestInterceptor        bool `json:"request_interceptor"`
	RequestLifecyclePlugin    bool `json:"request_lifecycle_plugin"`
	ResponseBeforeTranslator  bool `json:"response_before_translator"`
	ResponseInterceptor       bool `json:"response_interceptor"`
	StreamChunkInterceptor    bool `json:"response_stream_interceptor"`
	WebSocketResponseObserver bool `json:"websocket_response_observer"`
	UsagePlugin               bool `json:"usage_plugin"`
	ManagementAPI             bool `json:"management_api"`
}

type requestInterceptRequest struct {
	RequestID      string
	TraceID        string
	SourceFormat   string
	ToFormat       string
	Model          string
	RequestedModel string
	Stream         bool
	Headers        http.Header
	Body           []byte
	Metadata       map[string]any
}

type requestCompletion struct {
	RequestID      string
	TraceID        string
	SourceFormat   string
	Model          string
	RequestedModel string
	Stream         bool
	Outcome        string
	StatusCode     int
	Error          string
	StartedAt      time.Time
	CompletedAt    time.Time
	Metadata       map[string]any
}

type responseInterceptRequest struct {
	RequestID       string
	SourceFormat    string
	Model           string
	RequestedModel  string
	Stream          bool
	RequestHeaders  http.Header
	ResponseHeaders http.Header
	OriginalRequest []byte
	RequestBody     []byte
	Body            []byte
	StatusCode      int
	Metadata        map[string]any
}

type streamChunkInterceptRequest struct {
	RequestID       string
	SourceFormat    string
	Model           string
	RequestedModel  string
	RequestHeaders  http.Header
	ResponseHeaders http.Header
	OriginalRequest []byte
	RequestBody     []byte
	Body            []byte
	ChunkIndex      int
	Metadata        map[string]any
}

type webSocketResponseEvent struct {
	RequestID      string
	TraceID        string
	SourceFormat   string
	Model          string
	RequestedModel string
	Provider       string
	AuthID         string
	AuthLabel      string
	AuthType       string
	EventType      string
	Payload        []byte
}

type usageRecord struct {
	Provider        string
	BaseURL         string
	ExecutorType    string
	Model           string
	Alias           string
	AuthID          string
	AuthIndex       string
	AuthType        string
	Source          string
	ReasoningEffort string
	ServiceTier     string
	RequestedAt     time.Time
	Latency         time.Duration
	TTFT            time.Duration
	Failed          bool
	Failure         struct {
		StatusCode int
		Body       string
	}
	Detail struct {
		InputTokens         int64
		OutputTokens        int64
		ReasoningTokens     int64
		CachedTokens        int64
		CacheReadTokens     int64
		CacheCreationTokens int64
		TotalTokens         int64
	}
	ResponseHeaders http.Header
}

type managementRegistration struct {
	Routes    []managementRoute `json:"routes,omitempty"`
	Resources []managementRoute `json:"resources,omitempty"`
}

type managementRoute struct {
	Method      string `json:"Method,omitempty"`
	Path        string
	Menu        string `json:"Menu,omitempty"`
	Description string
}

type managementRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Query   url.Values
	Body    []byte
}

type managementResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// requestInterceptResult 对应宿主 pluginapi.RequestInterceptResponse；Body 非空时替换请求体。
type requestInterceptResult struct {
	Body []byte
}

var emptyResult = []byte(`{"ok":true,"result":{}}`)

// dispatch 是所有宿主调用的唯一入口。抓取类钩子返回"不修改"的空结果；唯一的例外是配置了
// rewrite_env_timezone 且未关闭 rewrite_env_enabled 时，request.intercept_before 会返回改写过 environment_context 的请求体。
// 任何内部错误或 panic 都不能影响代理转发。
func dispatch(method string, request []byte) (out []byte) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logf("panic in %s: %v\n%s", method, recovered, debug.Stack())
			out = emptyResult
		}
	}()
	switch method {
	case methodPluginRegister, methodPluginReconfigure:
		var req lifecycleRequest
		if len(request) > 0 {
			if err := json.Unmarshal(request, &req); err != nil {
				return errorEnvelope("bad_request", err.Error())
			}
		}
		if req.SchemaVersion != 0 && req.SchemaVersion < 2 {
			return errorEnvelope("unsupported_host", "cpa-inspector requires host plugin schema version 2 or newer")
		}
		cfg, err := parseConfig(req.ConfigYAML)
		if err != nil {
			return errorEnvelope("bad_config", err.Error())
		}
		configureInspector(cfg)
		return okEnvelope(buildRegistration(cfg))
	case methodPluginQuiesce:
		flushInspector()
		return emptyResult
	case methodPluginShutdown:
		shutdownInspector()
		return emptyResult
	case methodManagementRegister:
		return okEnvelope(managementRoutes())
	case methodManagementHandle:
		var req managementRequest
		if err := json.Unmarshal(request, &req); err != nil {
			return errorEnvelope("bad_request", err.Error())
		}
		return okEnvelope(handleManagement(req))
	}

	ins := currentInspector()
	if ins == nil {
		return emptyResult
	}
	switch method {
	case methodRequestInterceptBefore, methodRequestInterceptAfter:
		var req requestInterceptRequest
		if err := json.Unmarshal(request, &req); err == nil {
			if method == methodRequestInterceptBefore && req.SourceFormat == "openai-response" {
				if body, notes := ins.env.rewrite(req.Body, req.Headers, req.Metadata); body != nil {
					ins.onRewrittenRequest(&req, body, notes)
					return okEnvelope(requestInterceptResult{Body: body})
				}
			}
			ins.onRequest(&req, method == methodRequestInterceptAfter)
		}
	case methodResponseNormalizeBefore:
		if req, ok := parseNormalizeRequest(request); ok {
			ins.onUpstreamChunk(req)
		}
	case methodResponseInterceptAfter:
		var req responseInterceptRequest
		if err := json.Unmarshal(request, &req); err == nil {
			ins.onDownstreamResponse(&req)
		}
	case methodResponseStreamChunk:
		var req streamChunkInterceptRequest
		if err := json.Unmarshal(request, &req); err == nil {
			ins.onDownstreamChunk(&req)
		}
	case methodWebSocketResponseEvent:
		var ev webSocketResponseEvent
		if err := json.Unmarshal(request, &ev); err == nil {
			ins.onWebSocketEvent(&ev)
		}
	case methodRequestComplete:
		var done requestCompletion
		if err := json.Unmarshal(request, &done); err == nil {
			ins.onComplete(&done)
		}
	case methodUsageHandle:
		var rec usageRecord
		if err := json.Unmarshal(request, &rec); err == nil {
			ins.onUsage(&rec)
		}
	default:
		return errorEnvelope("unknown_method", "unknown method: "+method)
	}
	return emptyResult
}

func buildRegistration(cfg config) registration {
	return registration{
		SchemaVersion: schemaVersion,
		Metadata: pluginMetadata{
			Name:    pluginID,
			Version: pluginVersion,
			Author:  "hxfeng1998",
			// 宿主要求 Name/Version/Author/GitHubRepository 四项非空，否则拒绝加载；面板会把仓库地址渲染成链接。
			GitHubRepository: repoURL,
			ConfigFields: []configField{
				{Name: "capture_upstream", Type: "boolean", Description: "抓取翻译前的原始上游响应与实际发往上游的请求体（灰测字段分析的核心数据源；流式长上下文下有额外开销）。"},
				{Name: "data_dir", Type: "string", Description: "数据目录：请求记录、字段基线与发现项持久化位置。"},
				{Name: "max_records", Type: "integer", Description: "最多保留的请求记录条数。"},
				{Name: "max_disk_mb", Type: "integer", Description: "请求记录占用磁盘上限（MB）。"},
				{Name: "max_body_mb", Type: "integer", Description: "单个请求/响应体保留上限（MB），超出部分只分析不保存。"},
				{Name: "learn_samples", Type: "integer", Description: "字段基线学习样本数：某作用域观测满该数量后，新出现的字段才会被报告为漂移。"},
				{Name: "scan_secrets", Type: "boolean", Description: "扫描发往上游的请求体中是否含密钥/私钥/带口令的连接串。"},
				{Name: "rewrite_env_enabled", Type: "boolean", Description: "是否改写 Codex 请求的时区与日期（需同时配置 rewrite_env_timezone）；关闭后请求原样转发，重新开启时沿用已有历史映射。"},
				{Name: "rewrite_env_timezone", Type: "string", Description: "将带 Codex 环境类型标记的请求日期与时区统一为该 IANA 时区（如 America/Los_Angeles），保留历史映射并按需追加当前日期；留空不改写。"},
			},
		},
		Capabilities: capabilities{
			RequestInterceptor:        true,
			RequestLifecyclePlugin:    true,
			ResponseBeforeTranslator:  cfg.CaptureUpstream,
			ResponseInterceptor:       true,
			StreamChunkInterceptor:    true,
			WebSocketResponseObserver: true,
			UsagePlugin:               true,
			ManagementAPI:             true,
		},
	}
}

func okEnvelope(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return errorEnvelope("encode_error", err.Error())
	}
	out, err := json.Marshal(envelope{OK: true, Result: raw})
	if err != nil {
		return errorEnvelope("encode_error", err.Error())
	}
	return out
}

func errorEnvelope(code, message string) []byte {
	out, err := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	if err != nil {
		return []byte(`{"ok":false,"error":{"code":"plugin_error","message":"encode error"}}`)
	}
	return out
}

func logf(format string, args ...any) {
	fmt.Printf("[cpa-inspector] "+format+"\n", args...)
}
