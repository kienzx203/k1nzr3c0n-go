package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// streamRequest is chatRequest plus the streaming flags.
type streamRequest struct {
	Model         string         `json:"model"`
	Messages      []Message      `json:"messages"`
	Tools         []ToolDef      `json:"tools,omitempty"`
	Temperature   float64        `json:"temperature"`
	MaxTokens     int            `json:"max_tokens,omitempty"`
	Stream        bool           `json:"stream"`
	StreamOptions *streamOptions `json:"stream_options,omitempty"`
}

type streamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

// streamChunk is one SSE delta frame.
type streamChunk struct {
	Choices []struct {
		Delta struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage"`
}

// ChatCompletionStream streams one assistant turn. onDelta is called with each
// content fragment as it arrives (empty fragments are skipped). It returns the
// fully assembled Turn (content + tool_calls) and token usage, matching the
// non-streaming ChatCompletion so the tool-calling loop is unchanged.
func (c *Client) ChatCompletionStream(ctx context.Context, msgs []Message, tools []ToolDef, onDelta func(string)) (*Turn, *Usage, error) {
	body, _ := json.Marshal(streamRequest{
		Model: c.Model, Messages: msgs, Tools: tools, Temperature: c.Temp, MaxTokens: 8192,
		Stream: true, StreamOptions: &streamOptions{IncludeUsage: true},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp chatResponse
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		if errResp.Error != nil {
			return nil, nil, fmt.Errorf("LLM error: %s", errResp.Error.Message)
		}
		return nil, nil, fmt.Errorf("LLM HTTP %d", resp.StatusCode)
	}

	var content strings.Builder
	toolAcc := map[int]*ToolCall{}
	var order []int
	var usage Usage
	finish := ""

	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var ch streamChunk
		if json.Unmarshal([]byte(data), &ch) != nil {
			continue
		}
		if ch.Usage != nil {
			usage.PromptTokens = ch.Usage.PromptTokens
			usage.CompletionTokens = ch.Usage.CompletionTokens
			usage.TotalTokens = ch.Usage.TotalTokens
		}
		if len(ch.Choices) == 0 {
			continue
		}
		d := ch.Choices[0]
		if d.FinishReason != "" {
			finish = d.FinishReason
		}
		if d.Delta.Content != "" {
			content.WriteString(d.Delta.Content)
			if onDelta != nil {
				onDelta(d.Delta.Content)
			}
		}
		for _, tc := range d.Delta.ToolCalls {
			acc, ok := toolAcc[tc.Index]
			if !ok {
				acc = &ToolCall{Type: "function"}
				toolAcc[tc.Index] = acc
				order = append(order, tc.Index)
			}
			if tc.ID != "" {
				acc.ID = tc.ID
			}
			if tc.Type != "" {
				acc.Type = tc.Type
			}
			if tc.Function.Name != "" {
				acc.Function.Name = tc.Function.Name
			}
			acc.Function.Arguments += tc.Function.Arguments
		}
	}
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		return nil, nil, err
	}

	turn := &Turn{Role: "assistant", Content: content.String(), FinishReas: finish}
	for _, idx := range order {
		turn.ToolCalls = append(turn.ToolCalls, *toolAcc[idx])
	}
	return turn, &usage, nil
}
