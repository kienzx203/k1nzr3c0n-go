package server

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/agent"
	runtimeconfig "github.com/Autumn-27/artex/config"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"github.com/Autumn-27/artex/ollama"
	"github.com/Autumn-27/norma/llm"
)

const settingLocalLLMOnly = "local_llm_only"
const settingLocalLLMCIDRs = "local_llm_allowed_cidrs"

// Environment policy is a floor: saved settings cannot disable an administrator's guard.
func (s *Server) applyLLMPolicy(cfg agent.Config) agent.Config {
	cfg.LocalLLMOnly, cfg.LocalLLMAllowedCIDRs = s.effectiveLLMPolicy()
	cfg.PolicyResolver = s.effectiveLLMPolicy
	return cfg
}
func (s *Server) effectiveLLMPolicy() (bool, []string) {
	if s == nil {
		return (*Manager)(nil).effectiveLLMPolicy()
	}
	return s.m.effectiveLLMPolicy()
}
func (m *Manager) effectiveLLMPolicy() (bool, []string) {
	strict, cidrs := runtimeconfig.LocalLLMPolicy()
	if m != nil && m.pg != nil {
		if raw, ok, err := m.pg.GetSetting(settingLocalLLMOnly); err != nil {
			strict = true
		} else if ok {
			saved, parseErr := strconv.ParseBool(raw)
			strict = strict || saved || parseErr != nil
		}
		cidrs = append(cidrs, m.savedLLMCIDRs()...)
	}
	if cidrs == nil {
		cidrs = []string{}
	}
	return strict, cidrs
}

// Editable ranges contain only the saved policy; environment ranges remain read-only.
func (s *Server) savedLLMCIDRs() []string {
	if s == nil {
		return []string{}
	}
	return s.m.savedLLMCIDRs()
}
func (m *Manager) savedLLMCIDRs() []string {
	cidrs := []string{}
	if m != nil && m.pg != nil {
		if raw, ok, err := m.pg.GetSetting(settingLocalLLMCIDRs); err == nil && ok {
			if json.Unmarshal([]byte(raw), &cidrs) != nil {
				return []string{}
			}
		}
	}
	if cidrs == nil {
		return []string{}
	}
	return cidrs
}
func (s *Server) saveLLMPolicy(on *bool, cidrs *[]string) error {
	if cidrs != nil {
		for _, v := range *cidrs {
			if _, err := netip.ParsePrefix(v); err != nil {
				return locale.Errorf("invalid local LLM allowed CIDR %q: %w", v, err)
			}
		}
		raw, _ := json.Marshal(*cidrs)
		if err := s.m.pg.SetSetting(settingLocalLLMCIDRs, string(raw)); err != nil {
			return err
		}
	}
	if on != nil {
		return s.m.pg.SetBool(settingLocalLLMOnly, *on)
	}
	return nil
}
func ollamaOptions(cfg agent.Config) ollama.Options {
	return ollama.Options{ContextWindow: cfg.CompactionWindow(), KeepAlive: cfg.KeepAlive, ThinkingType: cfg.ThinkingType, MaxTokens: cfg.MaxTokens, JSON: cfg.JSONOutput}
}
func ollamaClient(cfg agent.Config) (*ollama.Client, error) {
	client, err := cfg.HTTPClient()
	if err != nil {
		return nil, err
	}
	return ollama.NewClient(cfg.BaseURL, cfg.APIKey, client)
}
func (s *Server) listOllamaModels(w http.ResponseWriter, r *http.Request, cfg agent.Config) {
	client, err := ollamaClient(cfg)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": locale.ErrorMessage(responseLanguage(w), err)})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	models, err := client.ListModels(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": locale.ErrorMessage(responseLanguage(w), err)})
		return
	}
	names := make([]string, 0, len(models))
	details := make([]map[string]any, 0, len(models))
	for _, m := range models {
		name := m.Name
		if name == "" {
			name = m.Model
		}
		names = append(names, name)
		item := map[string]any{"name": name, "model": name, "details": m.Details, "capabilities": []string{}}
		if info, err := client.Show(ctx, name); err == nil {
			item["capabilities"] = info.Capabilities
			item["details"] = info.Details
		} else {
			item["error"] = locale.ErrorMessage(responseLanguage(w), err)
		}
		details = append(details, item)
	}
	writeJSON(w, 200, map[string]any{"ok": true, "models": names, "model_details": details})
}
func (s *Server) testOllama(w http.ResponseWriter, r *http.Request, cfg agent.Config) {
	client, err := ollamaClient(cfg)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": locale.ErrorMessage(responseLanguage(w), err)})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()
	start := time.Now()
	release, err := s.nativeGate(cfg).acquire(ctx)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": locale.ErrorMessage(responseLanguage(w), err)})
		return
	}
	defer release()
	d, err := client.Test(ctx, cfg.Model, ollamaOptions(cfg))
	// Preserve partial diagnostic evidence when a capability or runner check fails.
	raw, _ := json.Marshal(d)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	out["ok"], out["latency_ms"] = err == nil, time.Since(start).Milliseconds()
	if err != nil {
		out["error"] = locale.ErrorMessage(responseLanguage(w), err)
	}

	writeJSON(w, 200, out)
}

// A native endpoint has one admission gate even when several profiles select it.
type endpointGate struct {
	mu            sync.Mutex
	limit, active int
	changed       chan struct{}
}

func (g *endpointGate) acquire(ctx context.Context) (func(), error) {
	for {
		g.mu.Lock()
		if g.active < g.limit {
			g.active++
			g.mu.Unlock()
			var once sync.Once
			return func() {
				once.Do(func() { g.mu.Lock(); g.active--; close(g.changed); g.changed = make(chan struct{}); g.mu.Unlock() })
			}, nil
		}
		ch := g.changed
		g.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ch:
		}
	}
}

var nativeGates = struct {
	sync.Mutex
	gates map[string]*endpointGate
}{gates: map[string]*endpointGate{}}

func nativeEndpointKey(cfg agent.Config) string {
	return strings.TrimRight(ollama.NormalizeBaseURL(cfg.BaseURL), "/")
}
func nativeEndpointGate(cfg agent.Config) *endpointGate {
	n := cfg.MaxConcurrent
	if n <= 0 {
		n = 1
	}
	key := nativeEndpointKey(cfg)
	nativeGates.Lock()
	defer nativeGates.Unlock()
	g := nativeGates.gates[key]
	if g == nil {
		g = &endpointGate{limit: n, changed: make(chan struct{})}
		nativeGates.gates[key] = g
	} else {
		g.mu.Lock()
		if n < g.limit {
			g.limit = n
		}
		g.mu.Unlock()
	}
	return g
}
func (s *Server) profileConcurrencyProvider(prov llm.Provider, cfg agent.Config) llm.Provider {
	if cfg.Provider() != "ollama" {
		if cfg.MaxConcurrent <= 0 {
			return newConcurrencyProvider(prov, s.m)
		}
		return &concurrencyProvider{inner: prov, sem: make(chan struct{}, cfg.MaxConcurrent)}
	}
	gate := s.nativeGate(cfg)
	return &nativeAdmissionProvider{inner: &warmOllamaProvider{inner: prov, cfg: cfg}, gate: gate}
}

func (s *Server) nativeGate(cfg agent.Config) *endpointGate {
	gate := nativeEndpointGate(cfg)
	if s != nil && s.m != nil && s.m.pg != nil {
		limit := cfg.MaxConcurrent
		if limit <= 0 {
			limit = 1
		}
		if ps, err := s.m.pg.ListProfiles(); err == nil {
			for _, p := range ps {
				if p.Format == "ollama" && nativeEndpointKey(agent.ConfigFrom(p.Format, p.Model, p.BaseURL, "", "")) == nativeEndpointKey(cfg) {
					n := p.MaxConcurrent
					if n <= 0 {
						n = 1
					}
					if n < limit {
						limit = n
					}
				}
			}
		}
		gate.mu.Lock()
		gate.limit = limit
		close(gate.changed)
		gate.changed = make(chan struct{})
		gate.mu.Unlock()
	}
	return gate
}

type nativeAdmissionProvider struct {
	inner llm.Provider
	gate  *endpointGate
}

func (p *nativeAdmissionProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		release, err := p.gate.acquire(ctx)
		if err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		defer release()
		for ev, err := range p.inner.Stream(ctx, req) {
			if !yield(ev, err) {
				return
			}
		}
	}
}
func (p *nativeAdmissionProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	release, err := p.gate.acquire(ctx)
	if err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	defer release()
	return p.inner.Complete(ctx, req)
}

type warmOllamaProvider struct {
	inner llm.Provider
	cfg   agent.Config
}

type warmState struct {
	sync.Mutex
	ready bool
}

var warmStates = struct {
	sync.Mutex
	states map[string]*warmState
}{states: map[string]*warmState{}}

func modelWarmState(cfg agent.Config) *warmState {
	key := fmt.Sprintf("%s/%s/%d/%s", nativeEndpointKey(cfg), cfg.Model, cfg.CompactionWindow(), cfg.KeepAlive)
	warmStates.Lock()
	defer warmStates.Unlock()
	st := warmStates.states[key]
	if st == nil {
		st = &warmState{}
		warmStates.states[key] = st
	}
	return st
}
func (p *warmOllamaProvider) prepare(ctx context.Context) error {
	st := modelWarmState(p.cfg)
	st.Lock()
	defer st.Unlock()
	if st.ready {
		return nil
	}
	client, err := ollamaClient(p.cfg)
	if err != nil {
		return err
	}
	info, err := client.Show(ctx, p.cfg.Model)
	if err != nil {
		return err
	}
	if !info.Supports("tools") {
		return locale.Errorf("Ollama model %q does not support tool calling", p.cfg.Model)
	}
	if err := client.Warm(ctx, p.cfg.Model, ollamaOptions(p.cfg)); err != nil {
		return err
	}
	st.ready = true
	return nil
}
func (p *warmOllamaProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		if err := p.prepare(ctx); err != nil {
			yield(llm.StreamEvent{}, err)
			return
		}
		for ev, err := range p.inner.Stream(ctx, req) {
			if !yield(ev, err) {
				return
			}
		}
	}
}
func (p *warmOllamaProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if err := p.prepare(ctx); err != nil {
		return llm.Message{}, "", llm.Usage{}, err
	}
	return p.inner.Complete(ctx, req)
}

// prepareTaskOllama runs before goal decomposition or resumed workers, once per distinct selected native model.
func (s *Server) prepareTaskOllama(ctx context.Context, t *Task) bool {
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	seen := map[string]bool{}
	for _, role := range []string{"goals", "planner", "worker", "mainagent"} {
		r := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: role}
		cfg, ok := r.activeCfg()
		if !ok || cfg.Provider() != "ollama" {
			continue
		}
		key := fmt.Sprintf("%s/%s/%d/%s", nativeEndpointKey(cfg), cfg.Model, cfg.CompactionWindow(), cfg.KeepAlive)
		if seen[key] {
			continue
		}
		seen[key] = true
		gate := s.nativeGate(cfg)
		release, err := gate.acquire(ctx)
		if err == nil {
			p := warmOllamaProvider{cfg: cfg}
			st := modelWarmState(cfg)
			st.Lock()
			st.ready = false
			st.Unlock()
			err = p.prepare(ctx)
			release()
		}
		if err != nil {
			s.engine.emitActivity(t, db.Activity{Worker: "system", Kind: "error", Summary: locale.ErrorMessage(taskLanguage(s.m.pg, t.ID), err)})
			_ = s.m.SetTaskPaused(t.ID, true)
			s.engine.Pause(t.ID, err)
			return false
		}
	}
	return true
}
