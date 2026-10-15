// Package agent implements the ScopeWeaver-style AI agent layer: an
// LLM-driven assistant (GLM/Z.ai, OpenAI-compatible) that operates the recon
// platform through tools — launching workflows, watching runs, triaging
// findings, maintaining the asset graph and binding traffic evidence.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ── OpenAI-compatible chat client (GLM/Z.ai) ────────────────────────────────

type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"`
	Function FunctionCall `json:"function"`
}

type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type ToolDef struct {
	Type     string       `json:"type"`
	Function FunctionSpec `json:"function"`
}

type FunctionSpec struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Tools       []ToolDef `json:"tools,omitempty"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Role      string     `json:"role"`
			Content   string     `json:"content"`
			ToolCalls []ToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// Client talks to one OpenAI-compatible endpoint.
type Client struct {
	BaseURL string // e.g. https://api.z.ai/api/paas/v4
	APIKey  string
	Model   string
	Temp    float64
	HTTP    *http.Client
}

func NewClient(baseURL, apiKey, model string, temp float64) *Client {
	return &Client{
		BaseURL: trimSlash(baseURL), APIKey: apiKey, Model: model, Temp: temp,
		HTTP: &http.Client{Timeout: 180 * time.Second},
	}
}

func trimSlash(s string) string {
	if len(s) > 0 && s[len(s)-1] == '/' {
		return s[:len(s)-1]
	}
	return s
}

// ChatCompletion sends the conversation + tools, returns the assistant turn.
func (c *Client) ChatCompletion(ctx context.Context, msgs []Message, tools []ToolDef) (*Turn, *Usage, error) {
	body, _ := json.Marshal(chatRequest{
		Model: c.Model, Messages: msgs, Tools: tools, Temperature: c.Temp, MaxTokens: 8192,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	var cr chatResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, nil, fmt.Errorf("decode response (HTTP %d): %v", resp.StatusCode, err)
	}
	if cr.Error != nil {
		return nil, nil, fmt.Errorf("LLM error: %s", cr.Error.Message)
	}
	if len(cr.Choices) == 0 {
		return nil, nil, fmt.Errorf("LLM returned no choices (HTTP %d)", resp.StatusCode)
	}
	ch := cr.Choices[0]
	turn := &Turn{
		Role:       "assistant",
		Content:    ch.Message.Content,
		ToolCalls:  ch.Message.ToolCalls,
		FinishReas: ch.FinishReason,
	}
	u := Usage{
		PromptTokens: cr.Usage.PromptTokens, CompletionTokens: cr.Usage.CompletionTokens,
		TotalTokens: cr.Usage.TotalTokens,
	}
	return turn, &u, nil
}

// Turn is one assistant reply.
type Turn struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	FinishReas string     `json:"finish_reason"`
}

// Usage is the token accounting for one completion.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// HasToolCalls reports whether the turn requests tool execution.
func (t *Turn) HasToolCalls() bool { return len(t.ToolCalls) > 0 }
