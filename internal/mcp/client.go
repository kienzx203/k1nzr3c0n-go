// Package mcp implements a minimal Model Context Protocol stdio client:
// spawn server process → initialize handshake → tools/list → tools/call,
// exposing remote tools to the AI agent with mcp_<server>_<tool> names.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
)

// Tool is one remote MCP tool.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// Server is one connected MCP server process.
type Server struct {
	Name string
	Cmd  string
	Args []string

	mu      sync.Mutex
	proc    *exec.Cmd
	stdinW  *bufio.Writer
	nextID  int
	pending map[int]chan rpcResponse
	tools   []Tool
	closed  bool
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Connect spawns the server, handshakes and lists tools.
func Connect(ctx context.Context, name, cmd string, args []string) (*Server, error) {
	s := &Server{Name: name, Cmd: cmd, Args: args, pending: map[int]chan rpcResponse{}}
	proc := exec.CommandContext(ctx, cmd, args...)
	stdinPipe, err := proc.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := proc.StdoutPipe()
	if err != nil {
		return nil, err
	}
	proc.Stderr = nil
	if err := proc.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", cmd, err)
	}
	s.proc = proc
	s.stdinW = bufio.NewWriter(stdinPipe)

	// reader pump: route responses to pending calls, drop notifications
	go func() {
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var r rpcResponse
			if json.Unmarshal([]byte(line), &r) != nil || r.ID == 0 {
				continue // notification or malformed
			}
			s.mu.Lock()
			ch, ok := s.pending[r.ID]
			if ok {
				delete(s.pending, r.ID)
			}
			s.mu.Unlock()
			if ok {
				ch <- r
			}
		}
		s.mu.Lock()
		s.closed = true
		for id, ch := range s.pending {
			close(ch)
			delete(s.pending, id)
		}
		s.mu.Unlock()
	}()

	var initRes json.RawMessage
	if err := s.roundTrip(ctx, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "k1nzr3c0n-agent", "version": "1"},
	}, &initRes); err != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("initialize %s: %w", name, err)
	}
	s.notify("notifications/initialized", nil)

	var listRes struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := s.roundTrip(ctx, "tools/list", map[string]any{}, &listRes); err != nil {
		proc.Process.Kill()
		return nil, fmt.Errorf("tools/list %s: %w", name, err)
	}
	for _, t := range listRes.Tools {
		s.tools = append(s.tools, Tool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	return s, nil
}

// roundTrip sends a request and waits for the matching response (ctx-bound).
func (s *Server) roundTrip(ctx context.Context, method string, params any, out any) error {
	ch := make(chan rpcResponse, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return fmt.Errorf("server %s closed", s.Name)
	}
	s.nextID++
	id := s.nextID
	s.pending[id] = ch
	err := s.writeJSON(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	s.mu.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return ctx.Err()
	case r, ok := <-ch:
		if !ok {
			return fmt.Errorf("server %s terminated", s.Name)
		}
		if r.Error != nil {
			return fmt.Errorf("rpc %s: %s", method, r.Error.Message)
		}
		if out != nil && len(r.Result) > 0 {
			return json.Unmarshal(r.Result, out)
		}
		return nil
	}
}

func (s *Server) notify(method string, params any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.writeJSON(rpcRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (s *Server) writeJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := s.stdinW.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.stdinW.Flush()
}

// Tools returns the discovered tool list.
func (s *Server) Tools() []Tool { return s.tools }

// CallTool invokes one tool and returns the text content joined.
func (s *Server) CallTool(ctx context.Context, tool string, args map[string]any) (string, error) {
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := s.roundTrip(ctx, "tools/call", map[string]any{"name": tool, "arguments": args}, &res); err != nil {
		return "", err
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if c.Type == "text" {
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(c.Text)
		}
	}
	if res.IsError {
		return sb.String(), fmt.Errorf("MCP tool error: %s", sb.String())
	}
	return sb.String(), nil
}

// Close kills the server process.
func (s *Server) Close() {
	if s.proc != nil && s.proc.Process != nil {
		_ = s.proc.Process.Kill()
	}
}

var _ io.Reader = (io.Reader)(nil)
