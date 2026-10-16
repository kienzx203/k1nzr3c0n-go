package agent

import (
	"context"
	"fmt"
	"strings"
)

// ProfileRef is one failover-chain member.
type ProfileRef struct {
	ID      int64
	BaseURL string
	APIKey  string
	Model   string
	Temp    float64
}

// retryable inspects provider error strings for conditions where the NEXT
// profile should be tried (auth/quota/rate/server), mirroring llmpool.
func retryable(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, k := range []string{"401", "403", "429", "insufficient", "quota", "balance",
		"timeout", "500", "502", "503", "504", "connection refused", "no choices", "eof"} {
		if strings.Contains(s, k) {
			return true
		}
	}
	return false
}

// ChatWithFailover tries profiles in order; returns the successful turn and
// the 1-based profile index used. All-fail returns the last error.
func ChatWithFailover(ctx context.Context, profiles []ProfileRef, msgs []Message, tools []ToolDef) (*Turn, *Usage, int, error) {
	if len(profiles) == 0 {
		return nil, nil, 0, fmt.Errorf("no LLM profiles configured")
	}
	var lastErr error
	for i, p := range profiles {
		c := NewClient(p.BaseURL, p.APIKey, p.Model, p.Temp)
		turn, usage, err := c.ChatCompletion(ctx, msgs, tools)
		if err == nil {
			return turn, usage, i + 1, nil
		}
		lastErr = err
		if !retryable(err) {
			return nil, nil, 0, err // prompt/model-level error: failover won't help
		}
	}
	return nil, nil, 0, fmt.Errorf("all %d profiles failed, last: %w", len(profiles), lastErr)
}
