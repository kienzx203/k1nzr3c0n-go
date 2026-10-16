package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestConnectionLocalGatewayCredentialReuse(t *testing.T) {
	t.Setenv("SCOPEWEAVER_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("SCOPEWEAVER_LOCAL_LLM_ONLY", "false")
	t.Setenv("SCOPEWEAVER_LOCAL_LLM_ALLOWED_CIDRS", "")
	for _, format := range []string{"anthropic", "openai", "openai-responses"} {
		for _, scenario := range []string{"same normalized endpoint", "different endpoint", "different format", "different proxy", "nonlocal fallback"} {
			t.Run(format+"/"+scenario, func(t *testing.T) {
				targetFormat := format
				if scenario == "different format" {
					targetFormat = "openai"
					if format == "openai" {
						targetFormat = "anthropic"
					}
				}
				wantKey := "scopeweaver-local"
				if scenario == "same normalized endpoint" || scenario == "nonlocal fallback" {
					wantKey = "fixture-active-key"
				}
				var calls atomic.Int32
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					path, header, want := "/custom/chat/completions", "Authorization", "Bearer "+wantKey
					if targetFormat == "anthropic" {
						path, header, want = "/custom/v1/messages", "X-Api-Key", wantKey
					} else if targetFormat == "openai-responses" {
						path = "/custom/responses"
					}
					if r.Method != http.MethodPost || r.URL.Path != path || r.Header.Get(header) != want {
						t.Errorf("gateway received %s %s with %s=%q; want POST %s with %q", r.Method, r.URL.Path, header, r.Header.Get(header), path, want)
						http.Error(w, "fixture authentication failed", http.StatusUnauthorized)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					switch targetFormat {
					case "anthropic":
						fmt.Fprint(w, `{"role":"assistant","content":[{"type":"text","text":"OK"}],"stop_reason":"end_turn"}`)
					case "openai":
						fmt.Fprint(w, `{"choices":[{"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}]}`)
					default:
						fmt.Fprint(w, `{"status":"completed","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"OK"}]}]}`)
					}
				})
				gateway := httptest.NewServer(handler)
				defer gateway.Close()
				s := &Server{m: &Manager{}, llmCfg: agent.ConfigFrom(format, "fixture-model", gateway.URL+"/custom", "fixture-active-key", "")}
				baseURL, proxy := gateway.URL+"/custom", ""
				if scenario == "different endpoint" || scenario == "different proxy" || scenario == "nonlocal fallback" {
					other := httptest.NewServer(handler)
					defer other.Close()
					if scenario == "different endpoint" {
						baseURL = other.URL + "/custom"
					} else {
						proxy = other.URL
					}
					if scenario == "nonlocal fallback" {
						// The explicit local fixture proxy prevents any public network request.
						baseURL = "http://203.0.113.7/custom"
					}
				}
				if scenario == "same normalized endpoint" {
					suffix := map[string]string{"anthropic": "/v1/messages", "openai": "/chat/completions", "openai-responses": "/responses"}
					baseURL += suffix[targetFormat]
				}
				result := testGatewayConnection(t, s, targetFormat, baseURL, proxy)
				if result["ok"] != true || result["reply"] != "OK" || result["model"] != "fixture-model" || result["latency_ms"] == nil || calls.Load() != 1 {
					t.Fatalf("connection response=%v gateway calls=%d", result, calls.Load())
				}
			})
		}
	}
}

func TestConnectionNativeTargetDoesNotReuseActiveGatewayKey(t *testing.T) {
	t.Setenv("SCOPEWEAVER_CONFIG", filepath.Join(t.TempDir(), "missing.json"))
	t.Setenv("SCOPEWEAVER_LOCAL_LLM_ONLY", "false")
	t.Setenv("SCOPEWEAVER_LOCAL_LLM_ALLOWED_CIDRS", "")
	gateway := nativeFixture(t) // Asserts no Authorization header on every native request.
	s := &Server{m: &Manager{}, llmCfg: agent.ConfigFrom("openai", "fixture-model", gateway.URL, "fixture-active-key", "")}
	result := testGatewayConnection(t, s, "ollama", gateway.URL, "")
	if result["ok"] != true || result["tool_call_verified"] != true || result["context_verified"] != true {
		t.Fatalf("native diagnostics=%v", result)
	}
}

func testGatewayConnection(t *testing.T, s *Server, format, baseURL, proxy string) map[string]any {
	t.Helper()
	model := "fixture-model"
	if format == "ollama" {
		model = "test:latest"
	}
	raw, err := json.Marshal(map[string]any{"provider": format, "model": model, "base_url": baseURL, "proxy": proxy, "api_key": "", "streaming": false})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	s.testLLM(response, httptest.NewRequest(http.MethodPost, "/api/llm/test", bytes.NewReader(raw)))
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != http.StatusOK {
		t.Fatalf("HTTP %d response=%s decode error=%v", response.Code, response.Body, err)
	}
	return result
}
