// Package ollama implements native Ollama chat and model diagnostics.
package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Autumn-27/artex/locale"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultModel = "qwen2.5-coder:32b"
const DefaultBaseURL = "http://127.0.0.1:11434"
const DefaultKeepAlive = "30m"

// NormalizeBaseURL tolerates native and OpenAI API paths, retaining reverse-proxy prefixes.
func NormalizeBaseURL(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	if raw == "" {
		return DefaultBaseURL
	}
	for _, suffix := range []string{"/v1/chat/completions", "/api/chat", "/api/tags", "/api/show", "/api/ps", "/v1", "/api"} {
		if strings.HasSuffix(raw, suffix) {
			return strings.TrimSuffix(raw, suffix)
		}
	}
	return raw
}

type Options struct {
	ConnectAttempts int
	ConnectInterval time.Duration
	EmptyAttempts   int
	EmptyInterval   time.Duration
	ContextWindow   int
	KeepAlive       string
	ThinkingType    string
	MaxTokens       int
	JSON            bool
}

type Client struct {
	connectAttempts int
	connectInterval time.Duration
	baseURL, apiKey string
	http            *http.Client
}

func NewClient(baseURL, apiKey string, httpClient *http.Client) (*Client, error) {
	baseURL = NormalizeBaseURL(baseURL)
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, locale.Errorf("ollama: invalid base URL %q", baseURL)
	}
	if httpClient == nil {
		return nil, locale.Errorf("ollama: HTTP client is required")
	}
	return &Client{baseURL: baseURL, apiKey: apiKey, http: httpClient}, nil
}
func (c *Client) requestOnce(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if wrapped, ok := err.(*url.Error); ok {
			err = wrapped.Err
		}
		return nil, locale.Errorf("ollama: connection failed: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			var requested struct {
				Model string `json:"model"`
			}
			var failure struct {
				Error string `json:"error"`
			}
			_ = json.Unmarshal(data, &requested)
			missingModel := false
			if resp.StatusCode == http.StatusNotFound && requested.Model != "" && json.Unmarshal(b, &failure) == nil {
				message := strings.ToLower(failure.Error)
				model := strings.ToLower(requested.Model)
				for _, name := range []string{"'" + model + "'", `"` + model + `"`, model} {
					missingModel = missingModel || strings.Contains(message, "model "+name+" not found") || strings.Contains(message, "model "+name+" was not found")
				}
			}
			if missingModel {
				return nil, &HTTPError{StatusCode: resp.StatusCode, Message: locale.Errorf("ollama: HTTP 404: model %s was not found; run ollama pull %s: %s", requested.Model, requested.Model, strings.TrimSpace(string(b)))}
			}
			return nil, &HTTPError{StatusCode: resp.StatusCode, Message: locale.Errorf("ollama: HTTP %d: native endpoint unavailable; choose the OpenAI format for a compatible server or check the base URL: %s", resp.StatusCode, strings.TrimSpace(string(b)))}
		}
		return nil, &HTTPError{StatusCode: resp.StatusCode, Message: locale.Errorf("ollama: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))}
	}
	return resp, nil
}
func (c *Client) decode(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.request(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err = json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(out); err != nil {
		return locale.Errorf("ollama: invalid response: %w", err)
	}
	return nil
}

type Details struct {
	Family            string `json:"family"`
	ParameterSize     string `json:"parameter_size"`
	QuantizationLevel string `json:"quantization_level"`
}
type Model struct {
	Name    string  `json:"name"`
	Model   string  `json:"model"`
	Size    int64   `json:"size"`
	Details Details `json:"details"`
}
type ModelInfo struct {
	Capabilities []string       `json:"capabilities"`
	Details      Details        `json:"details"`
	ModelInfo    map[string]any `json:"model_info"`
}

func (m ModelInfo) Supports(capability string) bool {
	for _, c := range m.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}

type RunningModel struct {
	Name          string `json:"name"`
	Model         string `json:"model"`
	ContextLength int    `json:"context_length"`
	SizeVRAM      int64  `json:"size_vram"`
}
type Diagnostics struct {
	Model            string   `json:"model"`
	Capabilities     []string `json:"capabilities"`
	ToolsSupported   bool     `json:"tools_supported"`
	ToolCallVerified bool     `json:"tool_call_verified"`
	ContextLength    int      `json:"context_length"`
	ContextVerified  bool     `json:"context_verified"`
	LoadDurationMS   float64  `json:"load_duration_ms"`
	TokensPerSecond  float64  `json:"tokens_per_second"`
}

func (c *Client) ListModels(ctx context.Context) ([]Model, error) {
	var out struct {
		Models []Model `json:"models"`
	}
	err := c.decode(ctx, "GET", "/api/tags", nil, &out)
	var status *HTTPError
	if errors.As(err, &status) && (status.StatusCode == http.StatusNotFound || status.StatusCode == http.StatusMethodNotAllowed) {
		var compatible struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := c.decode(ctx, "GET", "/v1/models", nil, &compatible); err != nil {
			return nil, err
		}
		models := make([]Model, 0, len(compatible.Data))
		for _, model := range compatible.Data {
			if model.ID != "" {
				models = append(models, Model{Name: model.ID, Model: model.ID})
			}
		}
		return models, nil
	}
	return out.Models, err
}
func (c *Client) Show(ctx context.Context, model string) (ModelInfo, error) {
	var out ModelInfo
	err := c.decode(ctx, "POST", "/api/show", map[string]string{"model": model}, &out)
	return out, err
}
func (c *Client) Running(ctx context.Context) ([]RunningModel, error) {
	var out struct {
		Models []RunningModel `json:"models"`
	}
	err := c.decode(ctx, "GET", "/api/ps", nil, &out)
	return out.Models, err
}
func (c *Client) Warm(ctx context.Context, model string, opts Options) error {
	req := chatRequest{Model: model, Messages: []chatMessage{}, KeepAlive: keepAlive(opts), Options: options(opts), Stream: false}
	var out chatResponse
	if err := c.decode(ctx, "POST", "/api/chat", req, &out); err != nil {
		return err
	}
	if out.Error != "" {
		return locale.Errorf("ollama: %s", out.Error)
	}
	if !out.Done {
		return locale.Errorf("ollama: model warm-up returned an incomplete response")
	}
	return nil
}
func (c *Client) Test(ctx context.Context, model string, opts Options) (Diagnostics, error) {
	out := Diagnostics{Model: model}
	info, err := c.Show(ctx, model)
	if err != nil {
		return out, err
	}
	out.Capabilities = info.Capabilities
	out.ToolsSupported = info.Supports("tools")
	req := chatRequest{Model: model, Messages: []chatMessage{{Role: "user", Content: "Call the scopeweaver_ping tool with value OK to verify tool calling."}}, Tools: []chatTool{{Type: "function", Function: toolFunction{Name: "scopeweaver_ping", Description: "Connection test", Parameters: map[string]any{"type": "object", "properties": map[string]any{"value": map[string]any{"type": "string"}}, "required": []string{"value"}}}}}, KeepAlive: keepAlive(opts), Options: options(opts), Stream: false}
	var resp chatResponse
	if err := c.decode(ctx, "POST", "/api/chat", req, &resp); err != nil {
		return out, err
	}
	if resp.Error != "" {
		return out, locale.Errorf("ollama: %s", resp.Error)
	}
	for _, call := range resp.Message.ToolCalls {
		if call.Function.Name == "scopeweaver_ping" {
			var args struct {
				Value string `json:"value"`
			}
			if json.Unmarshal(call.Function.Arguments, &args) == nil && args.Value == "OK" {
				out.ToolCallVerified = true
			}
		}
	}
	out.LoadDurationMS = float64(resp.LoadDuration) / 1e6
	if resp.EvalDuration > 0 {
		out.TokensPerSecond = float64(resp.EvalCount) * 1e9 / float64(resp.EvalDuration)
	}
	running, err := c.Running(ctx)
	if err != nil {
		return out, err
	}
	for _, m := range running {
		if m.Name == model || m.Model == model || m.Name == model+":latest" {
			out.ContextLength = m.ContextLength
			out.ContextVerified = m.ContextLength >= contextWindow(opts)
		}
	}
	if !resp.Done {
		return out, locale.Errorf("ollama: diagnostic completion was incomplete")
	}
	if !out.ToolsSupported {
		return out, locale.Errorf("ollama: model %s does not declare tools capability; select a tool-capable model", model)
	}
	if !out.ToolCallVerified {
		return out, locale.Errorf("ollama: model %s did not execute the diagnostic tool call", model)
	}
	if !out.ContextVerified {
		return out, locale.Errorf("ollama: requested context %d was not verified in /api/ps (reported %d)", contextWindow(opts), out.ContextLength)
	}
	return out, nil
}
func contextWindow(opts Options) int {
	if opts.ContextWindow > 0 {
		return opts.ContextWindow
	}
	return 32768
}
func keepAlive(opts Options) string {
	if opts.KeepAlive != "" {
		return opts.KeepAlive
	}
	return DefaultKeepAlive
}
func options(opts Options) map[string]any {
	max := opts.MaxTokens
	if max <= 0 {
		max = 4096
	}
	return map[string]any{"num_ctx": contextWindow(opts), "num_predict": max}
}

// HTTPError preserves status classification for safe pre-response retries.
type HTTPError struct {
	StatusCode int
	Message    error
}

func (e *HTTPError) Error() string { return e.Message.Error() }
func (e *HTTPError) MessageForLanguage(lang locale.Lang) string {
	return locale.ErrorMessage(lang, e.Message)
}
func retries(n, defaultN int) int {
	if n < 0 {
		return 0
	}
	if n == 0 {
		return defaultN
	}
	return n
}
func retryWait(ctx context.Context, attempt int, interval time.Duration) error {
	if interval <= 0 {
		interval = 500 * time.Millisecond
		for i := 0; i < attempt && interval < 8*time.Second; i++ {
			interval *= 2
		}
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func (c *Client) request(ctx context.Context, method, path string, body any) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := c.requestOnce(ctx, method, path, body)
		if err == nil {
			return resp, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var status *HTTPError
		var network net.Error
		retryable := false
		if errors.As(err, &status) {
			retryable = status.StatusCode == 429 || status.StatusCode >= 500
		} else {
			retryable = errors.As(err, &network) && !strings.Contains(err.Error(), "local_llm_only")
		}
		if !retryable || attempt >= retries(c.connectAttempts, 3) {
			return nil, err
		}
		if err := retryWait(ctx, attempt, c.connectInterval); err != nil {
			return nil, err
		}
	}
}
