package server

// Claude SUBSCRIPTION (Pro/Max) OAuth login for the "claude-sub" LLM format.
//
// This performs the Claude Code OAuth Authorization-Code + PKCE flow so the
// operator can click "Login", authorize in the browser, paste the one-time code,
// and the app stores + AUTO-REFRESHES the subscription token (no manual token
// pasting). The access token is used by the claude-sub provider as a Bearer
// credential and bills against the Pro/Max PLAN.
//
// WARNING: this uses Claude Code's OAuth client to use the subscription OUTSIDE
// Claude Code, which VIOLATES Anthropic's terms and can get the account BANNED.
// Opt-in, operator-authorized. The authorize/token endpoints are reverse-engineered
// (community-sourced) and may change; the refresh params match claude_sub_llm.py.

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
	claudeOAuthAuthorize = "https://claude.ai/oauth/authorize"     // NOT platform.claude.com — the working CLI authorizes here
	claudeOAuthTokenURL  = "https://platform.claude.com/v1/oauth/token"
	claudeOAuthScope     = "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload"
	claudeOAuthLoopPort  = 8769 // local loopback listener that catches the browser callback
	claudeRefreshMargin  = 300  // refresh when the token is within 5 min of expiry
)

// claudeOAuthRedirect is the loopback redirect the authorize page sends the
// browser back to. The working `claude auth login` uses a localhost loopback +
// a local HTTP listener (NOT a manual copy-paste callback), so the whole login
// is automatic. The browser must run on the same host as this server.
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

// claudeResult is the completed (or failed) login, keyed by oauthID, that the
// UI polls for after the loopback listener has caught the callback.
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

// startClaudeLogin creates a pending PKCE login, ensures the loopback listener
// is running, and returns its id + authorize URL.
func startClaudeLogin() (oauthID, authURL string) {
	verifier, challenge := pkcePair()
	state := randB64(16)
	oauthID = randB64(12)
	ensureClaudeLoopListener()
	claudeMu.Lock()
	now := time.Now()
	for k, v := range claudePendingByState { // gc expired
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
	q.Set("client_id", claudeOAuthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", claudeOAuthRedirect())
	q.Set("scope", claudeOAuthScope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return oauthID, claudeOAuthAuthorize + "?" + q.Encode()
}

// ensureClaudeLoopListener lazily starts the loopback HTTP server that the
// authorize page redirects the browser to. Its /callback handler exchanges the
// code for tokens and parks the result for the UI to poll.
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
			fmt.Fprintf(w, "<h2>Login failed</h2><p>%s</p><p>Return to the app and try again.</p>", errMsg)
			return
		}
		_, _ = w.Write([]byte("<h2>✓ Logged in</h2><p>Return to the app tab — it will finish automatically. You can close this window.</p>"))
	}
	if !ok {
		finish(claudeSubCreds{}, "login session expired or unknown — start the login again")
		return
	}
	if e := q.Get("error"); e != "" {
		finish(claudeSubCreds{}, e+": "+q.Get("error_description"))
		return
	}
	c, err := exchangeClaudeCode(p.verifier, code)
	if err != nil {
		finish(claudeSubCreds{}, err.Error())
		return
	}
	finish(c, "")
}

// claudeTokenRequest posts a form-encoded token/refresh body and parses the
// credentials. Form encoding (not JSON) matches the working `claude auth login`.
func claudeTokenRequest(payload url.Values) (claudeSubCreds, error) {
	req, err := http.NewRequest("POST", claudeOAuthTokenURL, strings.NewReader(payload.Encode()))
	if err != nil {
		return claudeSubCreds{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, text/plain, */*")
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
func exchangeClaudeCode(verifier, code string) (claudeSubCreds, error) {
	return claudeTokenRequest(url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {claudeOAuthRedirect()},
		"client_id":     {claudeOAuthClientID},
		"code_verifier": {verifier},
	})
}

// refreshClaudeToken exchanges a refresh token for fresh credentials.
func refreshClaudeToken(refresh string) (claudeSubCreds, error) {
	c, err := claudeTokenRequest(url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {claudeOAuthClientID},
	})
	if err == nil && c.RefreshToken == "" {
		c.RefreshToken = refresh // some responses omit it → keep the old one
	}
	return c, err
}

// parseClaudeSubCreds reads the subscription credentials from the api_key field.
// It accepts several shapes so the operator can paste whatever they have:
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
// and starts the background refresher. A raw (non-JSON) key — e.g. a long-lived
// `claude setup-token` — is returned unchanged.
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
		writeJSON(w, 500, map[string]string{"error": "cannot start local login listener on port " +
			fmt.Sprint(claudeOAuthLoopPort) + " (" + lerr + ") — paste ~/.claude/.credentials.json into the key field instead"})
		return
	}
	writeJSON(w, 200, map[string]string{
		"oauth_id":      oauthID,
		"authorize_url": authURL,
		"redirect_uri":  claudeOAuthRedirect(),
	})
}

// handleClaudeOAuthResult is polled by the UI after the browser authorizes. It
// returns {status:"pending"} until the loopback listener has caught the
// callback, then {status:"ok", api_key} (or {status:"error"}).
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
	// api_key is the JSON blob the UI saves into the claude-sub profile.
	writeJSON(w, 200, map[string]any{"status": "ok", "api_key": string(b), "expires_at": res.creds.ExpiresAt})
}
