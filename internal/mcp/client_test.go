package mcp

import (
	"context"
	"testing"
	"time"
)

func TestConnectAndCall(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s, err := Connect(ctx, "mock", "python3", []string{"/tmp/opencode/mockmcp.py"})
	if err != nil {
		t.Skipf("mock unavailable: %v", err)
	}
	defer s.Close()
	if len(s.Tools()) != 1 || s.Tools()[0].Name != "echo" {
		t.Fatalf("tools = %+v", s.Tools())
	}
	out, err := s.CallTool(ctx, "echo", map[string]any{"text": "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if out != "echo: hello" {
		t.Fatalf("out = %q", out)
	}
}
