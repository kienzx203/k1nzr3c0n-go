package server

// Claude SUBSCRIPTION (Pro/Max) OAuth login for the "claude-sub" LLM format.
//
// Fully automatic loopback login, exactly as the real `claude` CLI does it:
// click → authorize in the browser → the browser is redirected to a local
// listener (http://localhost:PORT/callback) that catches the code, exchanges it
// and stores the subscription token (auto-refreshed). No code pasting.
//
// Settled from the real binary + a live test:
//   - authorize: https://claude.com/cai/oauth/authorize (CLAUDE_AI_AUTHORIZE_URL)
//   - redirect_uri: http://localhost:PORT/callback — the ONLY redirect kind the
//     Claude Code OAuth client accepts (its client-metadata registers only
//     http://localhost/callback + http://127.0.0.1/callback). The manual
//     platform.claude.com/oauth/code/callback redirect is rejected (consent 400).
//   - params: code=true, client_id, response_type=code, redirect_uri, scope,
//     code_challenge, code_challenge_method=S256, state
//   - token POST: Content-Type application/json, body {grant_type, code,
//     redirect_uri, client_id, code_verifier, state}, with a claude-cli
//     User-Agent (the token host is behind Cloudflare, which 1010-bans Go's UA).
//
// The browser must run on the same host as this server (localhost loopback).
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
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	claudeOAuthClientID  = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	claudeOAuthAuthorize = "https://claude.com/cai/oauth/authorize"
	claudeOAuthTokenURL  = "https://platform.claude.com/v1/oauth/token"
	claudeOAuthScope     = "org:create_api_key user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload user:plugins"
	claudeOAuthUA        = "claude-cli/2.1.314 (external, cli)"
	claudeOAuthLoopPort  = 54545 // local loopback listener that catches the browser callback
	claudeRefreshMargin  = 300   // refresh when the token is within 5 min of expiry
)

func claudeOAuthRedirect() string {
	return fmt.Sprintf("http://localhost:%d/callback", claudeOAuthLoopPort)
}

// claudeSubCreds is the JSON stored in a claude-sub profile's api_key column.
type claudeSubCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"` // unix seconds
}

type claudePending struct {
	verifier string
	oauthID  string
	exp      time.Time
}

// claudeResult is the finished (or failed) login, keyed by oauthID, the UI polls.
type claudeResult struct {
	creds claudeSubCreds
	err   string
	exp   time.Time
}

var (
	claudeMu             sync.Mutex
	claudePendingByState = map[string]claudePending{} // state -> pending login
	claudeResultByID     = map[string]claudeResult{}  // oauthID -> finished result
	claudeListenerOnce   sync.Once
	claudeListenerErr    string
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

// startClaudeLogin creates a pending PKCE login, ensures the loopback listener is
// running, and returns its id + the authorize URL to open.
func startClaudeLogin() (oauthID, authURL string) {
	verifier, challenge := pkcePair()
	state := randB64(16)
	oauthID = randB64(12)
	ensureClaudeLoopListener()
	claudeMu.Lock()
	now := time.Now()
	for k, v := range claudePendingByState {
		if now.After(v.exp) {
			delete(claudePendingByState, k)
		}
	}
	for k, v := range claudeResultByID {
		if now.After(v.exp) {
			delete(claudeResultByID, k)
		}
	}
	claudePendingByState[state] = claudePending{verifier: verifier, oauthID: oauthID, exp: now.Add(10 * time.Minute)}
	claudeMu.Unlock()
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", claudeOAuthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", claudeOAuthRedirect())
	q.Set("scope", claudeOAuthScope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return oauthID, claudeOAuthAuthorize + "?" + q.Encode()
}

// ensureClaudeLoopListener lazily starts the loopback HTTP server the authorize
// page redirects the browser to. Its /callback handler exchanges the code and
// parks the result for the UI to poll.
func ensureClaudeLoopListener() {
	claudeListenerOnce.Do(func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/callback", claudeLoopCallback)
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", claudeOAuthLoopPort))
		if err != nil {
			claudeMu.Lock()
			claudeListenerErr = err.Error()
			claudeMu.Unlock()
			return
		}
		go func() { _ = (&http.Server{Handler: mux}).Serve(ln) }()
	})
}

const claudeCallbackHTML = `<!doctype html><meta charset="utf-8"><title>Claude sign-in</title>
<style>body{font:15px/1.6 system-ui,sans-serif;background:#1a1a1a;color:#e6e6e6;display:grid;place-items:center;height:100vh;margin:0}
.c{text-align:center;max-width:360px;padding:32px}.t{font-size:40px}h1{font-size:18px;margin:.6em 0}p{color:#9a9a9a;margin:0}</style>
<div class="c"><div class="t">%s</div><h1>%s</h1><p>%s</p></div>`

func claudeLoopCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code, state := strings.TrimSpace(q.Get("code")), q.Get("state")
	claudeMu.Lock()
	p, ok := claudePendingByState[state]
	if ok {
		delete(claudePendingByState, state)
	}
	claudeMu.Unlock()
	finish := func(c claudeSubCreds, errMsg string) {
		if ok {
			claudeMu.Lock()
			claudeResultByID[p.oauthID] = claudeResult{creds: c, err: errMsg, exp: time.Now().Add(10 * time.Minute)}
			claudeMu.Unlock()
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if errMsg != "" {
			fmt.Fprintf(w, claudeCallbackHTML, "⚠️", "Sign-in failed", errMsg)
			return
		}
		fmt.Fprintf(w, claudeCallbackHTML, "✓", "Signed in", "You can close this tab and return to the app.")
	}
	if !ok {
		finish(claudeSubCreds{}, "login session expired — start the login again")
		return
	}
	if e := q.Get("error"); e != "" {
		finish(claudeSubCreds{}, strings.TrimSpace(e+": "+q.Get("error_description")))
		return
	}
	c, err := exchangeClaudeCode(p.verifier, code)
	if err != nil {
		finish(claudeSubCreds{}, err.Error())
		return
	}
	finish(c, "")
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

// exchangeClaudeCode swaps the one-time authorization code for credentials.
func exchangeClaudeCode(verifier, rawCode string) (claudeSubCreds, error) {
	code := strings.TrimSpace(rawCode)
	if i := strings.IndexByte(code, '#'); i >= 0 { // tolerate "code#state"
		code = code[:i]
	}
	return claudeTokenRequest(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  claudeOAuthRedirect(),
		"client_id":     claudeOAuthClientID,
		"code_verifier": verifier,
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
	claudeMu.Lock()
	lerr := claudeListenerErr
	claudeMu.Unlock()
	if lerr != "" {
		writeJSON(w, 500, map[string]string{"error": fmt.Sprintf(
			"cannot start the local login listener on port %d (%s)", claudeOAuthLoopPort, lerr)})
		return
	}
	writeJSON(w, 200, map[string]string{"oauth_id": oauthID, "authorize_url": authURL})
}

// handleClaudeOAuthResult is polled by the UI after the browser authorizes.
func (s *Server) handleClaudeOAuthResult(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.URL.Query().Get("oauth_id"))
	claudeMu.Lock()
	res, ok := claudeResultByID[id]
	if ok {
		delete(claudeResultByID, id)
	}
	claudeMu.Unlock()
	if !ok {
		writeJSON(w, 200, map[string]string{"status": "pending"})
		return
	}
	if res.err != "" {
		writeJSON(w, 200, map[string]string{"status": "error", "error": res.err})
		return
	}
	b, _ := json.Marshal(res.creds)
	writeJSON(w, 200, map[string]any{"status": "ok", "api_key": string(b), "expires_at": res.creds.ExpiresAt})
}
