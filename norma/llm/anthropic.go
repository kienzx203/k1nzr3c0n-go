package llm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"
)

// anthropicProvider speaks the Anthropic Messages API. When sub is true it is the
// "claude-sub" variant: it authenticates with a SUBSCRIPTION OAuth token
// (Authorization: Bearer) and prepends the Claude-Code billing/identity system
// block so the request bills against the Claude Pro/Max PLAN instead of an API
// key. This impersonates Claude Code to use the subscription outside it, which
// VIOLATES Anthropic's terms and can get the account banned — enabled only when
// the operator explicitly picks the claude-sub format. Mirrors claude_sub_llm.py
// (the CLIProxyAPI model). The normal (sub=false) path is unchanged: x-api-key.
type anthropicProvider struct {
	cfg Config
	sub bool
}

// claude-sub billing/identity constants (Claude Code fingerprint).
const (
	ccSubVersion = "2.1.280"
	ccSubFPSalt  = "59cf53e54c78"
)

// messagesURL is the /v1/messages endpoint. The subscription path needs the
// ?beta=true query (as claude_sub_llm.py uses) or the OAuth token is rejected.
func (p *anthropicProvider) messagesURL() string {
	if p.sub {
		return p.cfg.BaseURL + "/v1/messages?beta=true"
	}
	return p.cfg.BaseURL + "/v1/messages"
}

// setAuth sets the version header and the credential scheme for this provider.
func (p *anthropicProvider) setAuth(r *http.Request) {
	r.Header.Set("anthropic-version", p.cfg.APIVersion)
	if p.sub {
		r.Header.Set("authorization", "Bearer "+strings.TrimSpace(p.cfg.APIKey))
		return
	}
	r.Header.Set("x-api-key", p.cfg.APIKey)
}

// firstUserText returns the text of the first user message (for the billing fp).
func firstUserText(req CompletionRequest) string {
	for _, m := range req.Messages {
		if m.Role == RoleUser {
			return m.Text()
		}
	}
	return ""
}

// claudeSubBilling builds the Claude-Code billing/identity system block the
// subscription path needs (see claude_sub_llm.py _billing_header): a short
// fingerprint of three chars of the first user message, the Claude Code version,
// and a fixed salt.
func claudeSubBilling(req CompletionRequest) anthropicSystemBlock {
	rs := []rune(firstUserText(req))
	pick := func(i int) rune {
		if i < len(rs) {
			return rs[i]
		}
		return '0'
	}
	chars := string([]rune{pick(4), pick(7), pick(20)})
	sum := sha256.Sum256([]byte(ccSubFPSalt + chars + ccSubVersion))
	fp := hex.EncodeToString(sum[:])[:3]
	return anthropicSystemBlock{
		Type: "text",
		Text: fmt.Sprintf("x-anthropic-billing-header: cc_version=%s.%s; cc_entrypoint=cli; cch=00000;", ccSubVersion, fp),
	}
}

type anthropicSystemBlock struct {
	Type         string         `json:"type"`
	Text         string         `json:"text"`
	CacheControl map[string]any `json:"cache_control,omitempty"`
}

type anthropicReq struct {
	Model         string                 `json:"model"`
	System        []anthropicSystemBlock `json:"system,omitempty"`
	Messages      []Message              `json:"messages"`
	Tools         []anthropicTool        `json:"tools,omitempty"`
	MaxTokens     int                    `json:"max_tokens"`
	Temperature   *float64               `json:"temperature,omitempty"`
	StopSequences []string               `json:"stop_sequences,omitempty"`
	Thinking      *anthropicThinking     `json:"thinking,omitempty"`
	OutputConfig  *anthropicOutputConfig `json:"output_config,omitempty"`
	Stream        bool                   `json:"stream"`
}

// anthropicThinking is the "thinking":{"type":"enabled"|"disabled"} switch.
type anthropicThinking struct {
	Type string `json:"type"`
}

// anthropicOutputConfig carries the reasoning strength via
// "output_config":{"effort":"low"|"medium"|"high"|"max"}.
type anthropicOutputConfig struct {
	Effort string `json:"effort"`
}

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

func (p *anthropicProvider) buildBody(req CompletionRequest, stream bool) ([]byte, error) {
	maxTok := req.MaxTokens
	if maxTok == 0 {
		maxTok = 8192
	}
	// Effective thinking mode: a non-empty per-request override (req.Thinking)
	// wins over Config.ThinkingType. Thinking-type content blocks may be replayed
	// only when thinking is actively "enabled"; any other mode (incl. "disabled")
	// strips them so Anthropic does not reject the request.
	thinkingType := p.cfg.ThinkingType
	thinkingEnabled := thinkingType != ""
	if req.Thinking != "" {
		thinkingType = req.Thinking
		thinkingEnabled = req.Thinking == "enabled"
	}
	if p.sub && thinkingType == "" {
		// subscription path: a prompt can trip Adaptive thinking, which burns the
		// whole max_tokens on thinking blocks and returns empty text — default OFF
		// unless the profile explicitly enables it (matches claude_sub_llm.py).
		thinkingType = "disabled"
	}
	body := anthropicReq{
		Model:         p.cfg.Model,
		Messages:      mergeAdjacentSameRole(filterThinkingBlocks(req.Messages, thinkingEnabled)),
		MaxTokens:     maxTok,
		Temperature:   req.Temperature,
		StopSequences: req.Stop,
		Stream:        stream,
		System:        buildAnthropicSystem(req),
	}
	for _, t := range req.Tools {
		body.Tools = append(body.Tools, anthropicTool{Name: t.Name, Description: t.Description, InputSchema: t.InputSchema})
	}
	if thinkingType != "" {
		body.Thinking = &anthropicThinking{Type: thinkingType}
	}
	if p.cfg.ReasoningEffort != "" {
		body.OutputConfig = &anthropicOutputConfig{Effort: p.cfg.ReasoningEffort}
	}
	if p.sub { // subscription path: prepend the Claude-Code billing/identity block
		body.System = append([]anthropicSystemBlock{claudeSubBilling(req)}, body.System...)
	}
	return json.Marshal(body)
}

// buildAnthropicSystem splits the system prompt at DynamicBoundary, placing a
// cache breakpoint on the static prefix (FR-02.2).
func buildAnthropicSystem(req CompletionRequest) []anthropicSystemBlock {
	if len(req.System) == 0 {
		return nil
	}
	b := req.DynamicBoundary
	if b <= 0 {
		// No boundary set → no cache breakpoint.
		return []anthropicSystemBlock{{Type: "text", Text: joinSystem(req.System)}}
	}
	if b >= len(req.System) {
		// Boundary at/after the end → the whole system prompt is static; cache it
		// all in one block (an all-static prompt should still be cacheable).
		return []anthropicSystemBlock{{Type: "text", Text: joinSystem(req.System), CacheControl: map[string]any{"type": "ephemeral"}}}
	}
	return []anthropicSystemBlock{
		{Type: "text", Text: joinSystem(req.System[:b]), CacheControl: map[string]any{"type": "ephemeral"}},
		{Type: "text", Text: joinSystem(req.System[b:])},
	}
}

func (p *anthropicProvider) Stream(ctx context.Context, req CompletionRequest) iter.Seq2[StreamEvent, error] {
	return func(yield func(StreamEvent, error) bool) {
		body, err := p.buildBody(req, true)
		if err != nil {
			yield(StreamEvent{}, err)
			return
		}
		resp, err := doStream(ctx, p.cfg, p.messagesURL(), body, func(r *http.Request) {
			r.Header.Set("content-type", "application/json")
			p.setAuth(r)
			r.Header.Set("accept", "text/event-stream")
		}, "anthropic")
		if err != nil {
			yield(StreamEvent{}, err)
			return
		}
		defer resp.Body.Close()
		scan := newSSEScanner(resp.Body)
		for {
			_, data, serr := scan.next()
			if serr == io.EOF {
				return
			}
			if serr != nil {
				yield(StreamEvent{}, serr)
				return
			}
			if data == "" {
				continue
			}
			ev, ok, perr := parseAnthropicFrame(data)
			if perr != nil {
				yield(StreamEvent{}, perr)
				return
			}
			if !ok {
				continue
			}
			if !yield(ev, nil) {
				return
			}
		}
	}
}

// Complete performs a real non-streaming completion: it sends stream:false and
// parses the single JSON response from /v1/messages into a full assistant
// Message, returning it with the stop reason and normalized usage.
func (p *anthropicProvider) Complete(ctx context.Context, req CompletionRequest) (Message, string, Usage, error) {
	body, err := p.buildBody(req, false)
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	resp, err := doStream(ctx, p.cfg, p.messagesURL(), body, func(r *http.Request) {
		r.Header.Set("content-type", "application/json")
		p.setAuth(r)
		r.Header.Set("accept", "application/json")
	}, "anthropic")
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return Message{}, "", Usage{}, err
	}
	return parseAnthropicResponse(raw)
}

// parseAnthropicResponse decodes a non-streaming Messages API response into the
// neutral Message model. Anthropic already speaks the content-block shape, so
// text/thinking/tool_use blocks map across directly.
func parseAnthropicResponse(raw []byte) (Message, string, Usage, error) {
	var r struct {
		Type    string `json:"type"`
		Content []struct {
			Type      string          `json:"type"`
			Text      string          `json:"text"`
			Thinking  string          `json:"thinking"`
			Signature string          `json:"signature"`
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
		} `json:"content"`
		StopReason string          `json:"stop_reason"`
		Usage      *anthropicUsage `json:"usage"`
		Error      *struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return Message{}, "", Usage{}, fmt.Errorf("anthropic: decode response: %w (body: %s)", err, truncate(string(raw), 500))
	}
	if r.Error != nil || r.Type == "error" {
		msg := "error response"
		if r.Error != nil {
			msg = r.Error.Message
		}
		return Message{}, "", Usage{}, fmt.Errorf("anthropic: %s", msg)
	}
	var usage Usage
	if r.Usage != nil {
		usage = r.Usage.norm()
	}
	var blocks []ContentBlock
	for _, b := range r.Content {
		switch b.Type {
		case "text":
			if b.Text != "" {
				blocks = append(blocks, TextBlock(b.Text))
			}
		case "thinking":
			blocks = append(blocks, ContentBlock{Type: BlockThinking, Thinking: b.Thinking, Signature: b.Signature})
		case "tool_use":
			in := b.Input
			if len(in) == 0 {
				in = json.RawMessage("{}")
			}
			blocks = append(blocks, ContentBlock{Type: BlockToolUse, ID: b.ID, Name: b.Name, Input: in})
		}
	}
	return Message{Role: RoleAssistant, Content: blocks}, r.StopReason, usage, nil
}

func parseAnthropicFrame(data string) (StreamEvent, bool, error) {
	var f struct {
		Type         string `json:"type"`
		ContentBlock struct {
			Type string `json:"type"`
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"content_block"`
		Delta struct {
			Type        string `json:"type"`
			Text        string `json:"text"`
			PartialJSON string `json:"partial_json"`
			Thinking    string `json:"thinking"`
			Signature   string `json:"signature"`
			StopReason  string `json:"stop_reason"`
		} `json:"delta"`
		Usage   *anthropicUsage `json:"usage"`
		Message struct {
			Usage *anthropicUsage `json:"usage"`
		} `json:"message"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(data), &f); err != nil {
		return StreamEvent{}, false, nil // tolerate non-JSON keepalives
	}
	switch f.Type {
	case "message_start":
		if f.Message.Usage != nil {
			// Anthropic reports the full input side (input + cache read/creation) in
			// BOTH message_start and message_delta. To avoid double-counting when the
			// accumulator folds both events, message_start carries ONLY the input side
			// and message_delta carries ONLY output. The initial output_tokens here is
			// a placeholder (≈1), so drop it — the real output comes from message_delta.
			u := f.Message.Usage.norm()
			u.OutputTokens = 0
			return StreamEvent{Type: SEMessageStart, Usage: u}, true, nil
		}
	case "content_block_start":
		if f.ContentBlock.Type == "tool_use" {
			return StreamEvent{Type: SEToolUseStart, ToolID: f.ContentBlock.ID, ToolName: f.ContentBlock.Name}, true, nil
		}
	case "content_block_delta":
		switch f.Delta.Type {
		case "text_delta":
			return StreamEvent{Type: SETextDelta, Text: f.Delta.Text}, true, nil
		case "thinking_delta":
			return StreamEvent{Type: SEThinkingDelta, Text: f.Delta.Thinking}, true, nil
		case "signature_delta":
			return StreamEvent{Type: SEThinkingSignature, Text: f.Delta.Signature}, true, nil
		case "input_json_delta":
			return StreamEvent{Type: SEToolInputJSON, Text: f.Delta.PartialJSON}, true, nil
		}
	case "message_delta":
		ev := StreamEvent{Type: SEMessageDelta, StopReason: f.Delta.StopReason}
		if f.Usage != nil {
			// Only output here — the input side (input/cache) was already counted at
			// message_start; message_delta re-echoes it, so counting it again would
			// double the input/cache totals.
			ev.Usage = Usage{OutputTokens: f.Usage.OutputTokens}
		}
		return ev, true, nil
	case "message_stop":
		return StreamEvent{Type: SEMessageStop}, true, nil
	case "error":
		msg := "stream error"
		if f.Error != nil {
			msg = f.Error.Message
		}
		return StreamEvent{}, false, fmt.Errorf("anthropic: %s", msg)
	}
	return StreamEvent{}, false, nil
}

type anthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
}

// norm maps Anthropic usage to the canonical Usage. InputTokens is the TOTAL input
// INCLUDING cached tokens (OpenAI-style: prompt_tokens semantics) — Anthropic's raw
// input_tokens counts only the non-cached portion, so cache read+creation are folded
// in. CacheReadTokens/CacheWriteTokens are the cached SUBSET (⊆ InputTokens).
func (u anthropicUsage) norm() Usage {
	return Usage{
		InputTokens:      u.InputTokens + u.CacheReadInputTokens + u.CacheCreationInputTokens,
		OutputTokens:     u.OutputTokens,
		CacheReadTokens:  u.CacheReadInputTokens,
		CacheWriteTokens: u.CacheCreationInputTokens,
	}
}

// filterThinkingBlocks normalizes message history before it is sent to the
// Anthropic Messages API. It strips thinking-type content blocks when thinking
// is disabled (Anthropic rejects replayed thinking blocks without the thinking
// parameter enabled), and drops any message left with no content blocks —
// Anthropic rejects an empty content array. An empty message arrives here two
// ways: a thinking-only turn that collapses to empty once thinking is stripped,
// or an empty/truncated assistant turn (only reasoning, or nothing) that was
// recorded with no text or tool_use. (A thinking-only turn WITH thinking
// enabled keeps its thinking block — that is valid content and must be
// replayed.)
func filterThinkingBlocks(msgs []Message, thinkingEnabled bool) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		content := m.Content
		if !thinkingEnabled {
			filtered := make([]ContentBlock, 0, len(content))
			for _, b := range content {
				if b.Type != BlockThinking {
					filtered = append(filtered, b)
				}
			}
			content = filtered
		}
		if len(content) == 0 {
			continue // empty content array is rejected by Anthropic — drop it
		}
		if len(content) == len(m.Content) {
			out = append(out, m)
		} else {
			out = append(out, Message{Role: m.Role, Content: content})
		}
	}
	return out
}

// mergeAdjacentSameRole coalesces consecutive same-role messages into one by
// concatenating their content blocks. Anthropic requires messages to alternate
// user/assistant; dropping an empty turn in filterThinkingBlocks can leave two
// adjacent user messages (e.g. a tool result followed by a resume nudge, once
// the empty assistant between them is gone), which the API would reject with
// "roles must alternate". Merging preserves alternation without losing content.
// A fresh content slice is built on merge so the caller's message backing
// arrays are never mutated.
func mergeAdjacentSameRole(msgs []Message) []Message {
	out := make([]Message, 0, len(msgs))
	for _, m := range msgs {
		if n := len(out); n > 0 && out[n-1].Role == m.Role {
			merged := make([]ContentBlock, 0, len(out[n-1].Content)+len(m.Content))
			merged = append(merged, out[n-1].Content...)
			merged = append(merged, m.Content...)
			out[n-1].Content = merged
			continue
		}
		out = append(out, m)
	}
	return out
}
