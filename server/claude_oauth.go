package server

// Claude SUBSCRIPTION (Pro/Max) support for the "claude-sub" LLM format.
//
// The in-browser OAuth flow does NOT work for a third-party app (Anthropic only
// completes consent for the genuine Claude Code client), so profiles are seeded
// from the token the real `claude` CLI already obtained on this host
// (~/.claude/.credentials.json). `scripts/deploy.sh` calls POST
// /api/llm/claude/seed, which creates one claude-sub profile per supported model
// and activates Opus by default. The stored key auto-refreshes.
//
// Runtime shape (norma): Authorization: Bearer <token>, anthropic-beta:
// oauth-2025-04-20, POST /v1/messages?beta=true, first system block = the Claude
// Code identity line; thinking is omitted for Claude 5.x (they reject disabled).
//
// WARNING: using the subscription outside Claude Code VIOLATES Anthropic's terms
// and can get the account BANNED. Opt-in, operator-authorized.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

const (
	claudeOAuthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	claudeOAuthTokenURL = "https://platform.claude.com/v1/oauth/token"
	claudeOAuthUA       = "claude-cli/2.1.314 (external, cli)"
	claudeRefreshMargin = 300 // refresh when the token is within 5 min of expiry
)

// claudeSeedModels are the subscription-callable models seeded as profiles, in
// order; the first (Opus 4.8) is activated on the first seed. All verified
// against the API with a real subscription token.
var claudeSeedModels = []string{
	"claude-opus-4-8",
	"claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-1",
	"claude-sonnet-4-5", "claude-haiku-4-5",
}

const claudeLocalMissing = "no readable ~/.claude/.credentials.json on the server — run `claude` and log in on this host (as the service user)"

// claudeSubCreds is the JSON stored in a claude-sub profile's api_key column.
type claudeSubCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"` // unix seconds
}

// claudeTokenRequest posts a refresh JSON body and parses the credentials. The
// token host is behind Cloudflare, which 403/1010-bans Go's default User-Agent,
// so a claude-cli UA is required.
func claudeTokenRequest(payload map[string]string) (claudeSubCreds, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", claudeOAuthTokenURL, strings.NewReader(string(b)))
	if err != nil {
		return claudeSubCreds{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", claudeOAuthUA)
	resp, err := (&http.Client{Timeout: 25 * time.Second}).Do(req)
	if err != nil {
		return claudeSubCreds{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != 200 {
		return claudeSubCreds{}, fmt.Errorf("claude oauth %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var r struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(data, &r); err != nil || r.AccessToken == "" {
		return claudeSubCreds{}, fmt.Errorf("claude oauth: unexpected token response")
	}
	exp := int64(3600)
	if r.ExpiresIn > 0 {
		exp = r.ExpiresIn
	}
	return claudeSubCreds{AccessToken: r.AccessToken, RefreshToken: r.RefreshToken, ExpiresAt: time.Now().Unix() + exp}, nil
}

// refreshClaudeToken exchanges a refresh token for fresh credentials.
func refreshClaudeToken(refresh string) (claudeSubCreds, error) {
	c, err := claudeTokenRequest(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refresh,
		"client_id":     claudeOAuthClientID,
	})
	if err == nil && c.RefreshToken == "" {
		c.RefreshToken = refresh // some responses omit it → keep the old one
	}
	return c, err
}

// parseClaudeSubCreds reads the subscription credentials from the api_key field.
// It accepts several shapes:
//   - our flat JSON: {access_token, refresh_token, expires_at(sec)}
//   - Claude Code's ~/.claude/.credentials.json: {"claudeAiOauth":{accessToken,
//     refreshToken, expiresAt(ms)}}
//   - the CLIProxyAPI auth json: {access_token, refresh_token, expired(ISO8601)}
func parseClaudeSubCreds(apiKey string) (claudeSubCreds, bool) {
	s := strings.TrimSpace(apiKey)
	if !strings.HasPrefix(s, "{") {
		return claudeSubCreds{}, false
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(s), &raw) != nil {
		return claudeSubCreds{}, false
	}
	if v, ok := raw["claudeAiOauth"]; ok { // unwrap Claude Code's credentials file
		var inner map[string]json.RawMessage
		if json.Unmarshal(v, &inner) == nil {
			raw = inner
		}
	}
	getStr := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				var sv string
				if json.Unmarshal(v, &sv) == nil && sv != "" {
					return sv
				}
			}
		}
		return ""
	}
	c := claudeSubCreds{
		AccessToken:  getStr("access_token", "accessToken"),
		RefreshToken: getStr("refresh_token", "refreshToken"),
	}
	if c.AccessToken == "" {
		return claudeSubCreds{}, false
	}
	for _, k := range []string{"expires_at", "expiresAt"} {
		if v, ok := raw[k]; ok {
			var n int64
			if json.Unmarshal(v, &n) == nil && n > 0 {
				if n > 1_000_000_000_000 { // milliseconds → seconds
					n /= 1000
				}
				c.ExpiresAt = n
				break
			}
		}
	}
	if c.ExpiresAt == 0 {
		if iso := getStr("expired"); iso != "" {
			if t, err := time.Parse(time.RFC3339, iso); err == nil {
				c.ExpiresAt = t.Unix()
			}
		}
	}
	return c, true
}

// readLocalClaudeCreds reads Claude Code's login file from THIS server's home dir
// (~/.claude/.credentials.json, or $CLAUDE_CONFIG_DIR) and returns a normalized
// credentials blob.
func readLocalClaudeCreds() (blob, source string, ok bool) {
	var paths []string
	if d := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); d != "" {
		paths = append(paths, filepath.Join(d, ".credentials.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".claude", ".credentials.json"))
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if c, ok := parseClaudeSubCreds(string(b)); ok && c.AccessToken != "" {
			out, _ := json.Marshal(c)
			return string(out), p, true
		}
	}
	return "", "", false
}

// claudeSubAccessToken extracts the access token a claude-sub profile should use
// and starts the background refresher. A raw (non-JSON) key is returned unchanged.
func (s *Server) claudeSubAccessToken(apiKey string) string {
	if c, ok := parseClaudeSubCreds(apiKey); ok {
		s.ensureClaudeRefresher()
		return c.AccessToken
	}
	return apiKey
}

var claudeRefresherOnce sync.Once

// ensureClaudeRefresher lazily starts a goroutine that keeps every claude-sub
// profile's token fresh (refresh near expiry → persist → invalidate the provider
// cache), so a long-running task never hits an expired subscription token.
func (s *Server) ensureClaudeRefresher() {
	claudeRefresherOnce.Do(func() {
		go func() {
			for {
				time.Sleep(60 * time.Second)
				s.refreshClaudeSubProfiles()
			}
		}()
	})
}

func (s *Server) refreshClaudeSubProfiles() {
	if s.m == nil || s.m.pg == nil {
		return
	}
	profs, err := s.m.pg.ListProfiles()
	if err != nil {
		return
	}
	changed := false
	for _, p := range profs {
		if p == nil || p.Format != "claude-sub" {
			continue
		}
		pf, err := s.m.pg.ProfileByID(p.ID) // ListProfiles omits the key; refetch with it
		if err != nil || pf == nil {
			continue
		}
		c, ok := parseClaudeSubCreds(pf.APIKey)
		if !ok || c.RefreshToken == "" {
			continue
		}
		if time.Now().Unix() <= c.ExpiresAt-claudeRefreshMargin {
			continue // still fresh
		}
		nc, err := refreshClaudeToken(c.RefreshToken)
		if err != nil || nc.AccessToken == "" {
			continue
		}
		b, e := json.Marshal(nc)
		if e != nil {
			continue
		}
		// Update every claude-sub profile that shared this refresh token.
		for _, q := range profs {
			if q != nil && q.Format == "claude-sub" {
				if qf, err := s.m.pg.ProfileByID(q.ID); err == nil && qf != nil {
					if cc, ok := parseClaudeSubCreds(qf.APIKey); ok && cc.RefreshToken == c.RefreshToken {
						if s.m.pg.SetProfileKey(q.ID, string(b)) == nil {
							changed = true
						}
					}
				}
			}
		}
	}
	if changed {
		s.invalidateProfileAgents() // rebuild providers with the fresh token
	}
}

// ── HTTP handlers ────────────────────────────────────────────────────────────

// handleClaudeAdd creates (or updates) a single claude-sub profile for a model
// typed by hand — so a newly released model can be added without a code change —
// using the server's Claude Code login, and activates it. Profile name = model id.
func (s *Server) handleClaudeAdd(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var body struct {
		Model    string `json:"model"`
		Activate *bool  `json:"activate"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body)
	model := strings.TrimSpace(body.Model)
	if model == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "model is required"})
		return
	}
	blob, src, ok := readLocalClaudeCreds()
	if !ok {
		writeJSON(w, 200, map[string]any{"ok": false, "error": claudeLocalMissing})
		return
	}
	p := &db.LLMProfile{
		Name: model, Format: "claude-sub", BaseURL: "https://api.anthropic.com",
		Model: model, APIKey: blob, Streaming: true,
	}
	if profs, err := pg.ListProfiles(); err == nil {
		for _, ex := range profs {
			if ex != nil && ex.Name == model {
				p.ID = ex.ID
				break
			}
		}
	}
	id, err := pg.SaveProfile(p)
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if body.Activate == nil || *body.Activate {
		_ = pg.SetActiveProfile(id)
	}
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	writeJSON(w, 200, map[string]any{"ok": true, "id": id, "model": model, "source": src})
}

// handleClaudeSeed reads the server's Claude Code login and upserts one
// claude-sub profile per supported model (idempotent, by model-id name),
// activating Opus 4.8 on the first seed. Called by scripts/deploy.sh.
func (s *Server) handleClaudeSeed(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	blob, src, ok := readLocalClaudeCreds()
	if !ok {
		writeJSON(w, 200, map[string]any{"ok": false, "error": claudeLocalMissing})
		return
	}
	existing := map[string]*db.LLMProfile{}
	if profs, err := pg.ListProfiles(); err == nil {
		for _, p := range profs {
			if p != nil {
				existing[p.Name] = p
			}
		}
	}
	opusExisted := existing["claude-opus-4-8"] != nil
	var created []string
	var opusID int64
	for _, m := range claudeSeedModels {
		p := &db.LLMProfile{
			Name: m, Format: "claude-sub", BaseURL: "https://api.anthropic.com",
			Model: m, APIKey: blob, Streaming: true,
		}
		if ex, okk := existing[m]; okk {
			p.ID = ex.ID
		}
		id, err := pg.SaveProfile(p)
		if err != nil {
			continue
		}
		created = append(created, m)
		if m == "claude-opus-4-8" {
			opusID = id
		}
	}
	if !opusExisted && opusID != 0 { // first seed: make Opus 4.8 the active profile
		_ = pg.SetActiveProfile(opusID)
	}
	s.invalidateProfileAgents()
	s.reapplyActiveProfile()
	writeJSON(w, 200, map[string]any{"ok": true, "created": created, "source": src})
}
