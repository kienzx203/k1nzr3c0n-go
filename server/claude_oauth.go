package server

// Claude SUBSCRIPTION (Pro/Max) OAuth login for the "claude-sub" LLM format.
//
// This renders the authorize URL BYTE-FOR-BYTE like the real `claude` CLI login
// (verified by diffing the CLI's own URL): authorize at claude.com/cai, the
// manual callback redirect, code=true, the 7 CLI scopes, PKCE S256.
//
//   authorize   https://claude.com/cai/oauth/authorize
//   redirect    https://platform.claude.com/oauth/code/callback   (MANUAL — shows the code)
//   token       https://platform.claude.com/v1/oauth/token        (JSON body, claude-cli UA)
//   params      code=true, client_id, response_type=code, redirect_uri, scope,
//               code_challenge, code_challenge_method=S256, state
//   exchange    {grant_type, code, redirect_uri, client_id, code_verifier, state}
//
// Flow: click → authorize in the browser → the callback page shows a code →
// paste it → exchange → store the subscription token (auto-refreshed).
//
// WARNING: using the subscription outside Claude Code VIOLATES Anthropic's terms
// and can get the account BANNED. Opt-in, operator-authorized.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	claudeOAuthClientID  = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	claudeOAuthAuthorize = "https://claude.com/cai/oauth/authorize"
	claudeOAuthTokenURL  = "https://platform.claude.com/v1/oauth/token"
	claudeOAuthRedirect  = "https://platform.claude.com/oauth/code/callback"
	claudeOAuthScope     = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload user:plugins"
	claudeOAuthUA        = "claude-cli/2.1.314 (external, cli)"
	claudeRefreshMargin  = 300 // refresh when the token is within 5 min of expiry
)

// claudeSubCreds is the JSON stored in a claude-sub profile's api_key column.
type claudeSubCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"` // unix seconds
}

type claudePending struct {
	verifier string
	state    string
	exp      time.Time
}

var (
	claudePendingMu sync.Mutex
	claudePendingM  = map[string]claudePending{}
)

func randB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// pkcePair returns a PKCE verifier (48 random bytes, matching the CLI) and its
// S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = randB64(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// startClaudeLogin creates a pending PKCE login and returns its id + authorize URL
// built exactly like the CLI (query keys appended in the CLI's order).
func startClaudeLogin() (oauthID, authURL string) {
	verifier, challenge := pkcePair()
	state := randB64(16)
	oauthID = randB64(12)
	claudePendingMu.Lock()
	for k, v := range claudePendingM {
		if time.Now().After(v.exp) {
			delete(claudePendingM, k)
		}
	}
	claudePendingM[oauthID] = claudePending{verifier: verifier, state: state, exp: time.Now().Add(10 * time.Minute)}
	claudePendingMu.Unlock()
	// Build in the CLI's exact parameter order (url.Values.Encode would re-sort).
	esc := url.QueryEscape
	authURL = claudeOAuthAuthorize + "?" +
		"code=true" +
		"&client_id=" + esc(claudeOAuthClientID) +
		"&response_type=code" +
		"&redirect_uri=" + esc(claudeOAuthRedirect) +
		"&scope=" + esc(claudeOAuthScope) +
		"&code_challenge=" + esc(challenge) +
		"&code_challenge_method=S256" +
		"&state=" + esc(state)
	return oauthID, authURL
}

// claudeTokenRequest posts a token/refresh JSON body and parses the credentials.
func claudeTokenRequest(payload map[string]string) (claudeSubCreds, error) {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", claudeOAuthTokenURL, strings.NewReader(string(b)))
	if err != nil {
		return claudeSubCreds{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	// The token host is behind Cloudflare, which 403/1010-bans Go's default UA.
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

// exchangeClaudeCode swaps the one-time authorization code for credentials. The
// manual callback page shows the code as "<code>#<state>"; we split it and send
// both, exactly as the CLI's exchange does.
func exchangeClaudeCode(oauthID, rawCode string) (claudeSubCreds, error) {
	claudePendingMu.Lock()
	p, ok := claudePendingM[oauthID]
	if ok {
		delete(claudePendingM, oauthID)
	}
	claudePendingMu.Unlock()
	if !ok || time.Now().After(p.exp) {
		return claudeSubCreds{}, fmt.Errorf("login session expired — start the login again")
	}
	code, state := strings.TrimSpace(rawCode), p.state
	if i := strings.IndexByte(code, '#'); i >= 0 {
		if s := code[i+1:]; s != "" {
			state = s
		}
		code = code[:i]
	}
	return claudeTokenRequest(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  claudeOAuthRedirect,
		"client_id":     claudeOAuthClientID,
		"code_verifier": p.verifier,
		"state":         state,
	})
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
// It accepts several shapes so a profile key can also be pasted by hand:
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
		if b, e := json.Marshal(nc); e == nil {
			if s.m.pg.SetProfileKey(p.ID, string(b)) == nil {
				changed = true
			}
		}
	}
	if changed {
		s.invalidateProfileAgents() // rebuild providers with the fresh token
	}
}

// ── HTTP handlers ───────────────────────────────────────────────────────────

func (s *Server) handleClaudeOAuthStart(w http.ResponseWriter, r *http.Request) {
	oauthID, authURL := startClaudeLogin()
	writeJSON(w, 200, map[string]string{
		"oauth_id":      oauthID,
		"authorize_url": authURL,
		"redirect_uri":  claudeOAuthRedirect,
	})
}

// handleClaudeLocalImport reads Claude Code's own login file from THIS server's
// home dir (~/.claude/.credentials.json, or $CLAUDE_CONFIG_DIR) and returns a
// normalized credentials blob the UI drops into the profile key. This is the
// reliable path: the browser OAuth consent only succeeds when initiated by the
// genuine Claude Code, so we reuse the token the real `claude` CLI already
// obtained on this host — no browser, no consent.
func (s *Server) handleClaudeLocalImport(w http.ResponseWriter, r *http.Request) {
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
			writeJSON(w, 200, map[string]any{"ok": true, "api_key": string(out), "expires_at": c.ExpiresAt, "source": p})
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": false,
		"error": "no readable ~/.claude/.credentials.json on the server — run `claude` and log in on this host, or paste the file contents into the key field"})
}

func (s *Server) handleClaudeOAuthExchange(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OAuthID string `json:"oauth_id"`
		Code    string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	c, err := exchangeClaudeCode(strings.TrimSpace(in.OAuthID), in.Code)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	b, _ := json.Marshal(c)
	writeJSON(w, 200, map[string]any{"api_key": string(b), "expires_at": c.ExpiresAt})
}
