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
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	claudeOAuthClientID  = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	claudeOAuthAuthorize = "https://claude.ai/oauth/authorize"
	claudeOAuthTokenURL  = "https://platform.claude.com/v1/oauth/token"
	claudeOAuthRedirect  = "https://platform.claude.com/oauth/code/callback"
	claudeOAuthScope     = "user:inference user:profile user:sessions:claude_code user:mcp_servers"
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

// pkcePair returns a PKCE verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = randB64(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// startClaudeLogin creates a pending PKCE login and returns its id + authorize URL.
func startClaudeLogin() (oauthID, authURL string) {
	verifier, challenge := pkcePair()
	state := randB64(16)
	oauthID = randB64(12)
	claudePendingMu.Lock()
	for k, v := range claudePendingM { // gc expired
		if time.Now().After(v.exp) {
			delete(claudePendingM, k)
		}
	}
	claudePendingM[oauthID] = claudePending{verifier: verifier, state: state, exp: time.Now().Add(10 * time.Minute)}
	claudePendingMu.Unlock()
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", claudeOAuthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", claudeOAuthRedirect)
	q.Set("scope", claudeOAuthScope)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return oauthID, claudeOAuthAuthorize + "?" + q.Encode()
}

// claudeTokenRequest posts a token/refresh form and parses the credentials. The
// endpoint expects application/x-www-form-urlencoded (JSON can time out).
func claudeTokenRequest(form url.Values) (claudeSubCreds, error) {
	req, err := http.NewRequest("POST", claudeOAuthTokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return claudeSubCreds{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("User-Agent", "axios/1.15.2")
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
	if i := strings.IndexByte(code, '#'); i >= 0 { // callback shows "<code>#<state>"
		state = code[i+1:]
		code = code[:i]
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("state", state)
	form.Set("client_id", claudeOAuthClientID)
	form.Set("redirect_uri", claudeOAuthRedirect)
	form.Set("code_verifier", p.verifier)
	return claudeTokenRequest(form)
}

// refreshClaudeToken exchanges a refresh token for fresh credentials.
func refreshClaudeToken(refresh string) (claudeSubCreds, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refresh)
	form.Set("client_id", claudeOAuthClientID)
	form.Set("scope", claudeOAuthScope)
	c, err := claudeTokenRequest(form)
	if err == nil && c.RefreshToken == "" {
		c.RefreshToken = refresh // some responses omit it → keep the old one
	}
	return c, err
}

// parseClaudeSubCreds returns the JSON credentials stored in api_key (if any).
func parseClaudeSubCreds(apiKey string) (claudeSubCreds, bool) {
	s := strings.TrimSpace(apiKey)
	if !strings.HasPrefix(s, "{") {
		return claudeSubCreds{}, false
	}
	var c claudeSubCreds
	if json.Unmarshal([]byte(s), &c) != nil || c.AccessToken == "" {
		return claudeSubCreds{}, false
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
	writeJSON(w, 200, map[string]string{
		"oauth_id":      oauthID,
		"authorize_url": authURL,
		"redirect_uri":  claudeOAuthRedirect,
	})
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
	// api_key is the JSON blob the UI saves into the claude-sub profile.
	writeJSON(w, 200, map[string]any{"api_key": string(b), "expires_at": c.ExpiresAt})
}
