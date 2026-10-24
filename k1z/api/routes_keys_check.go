package api

// Live validation of configured recon API keys: each key is tested against its
// provider's account/quota endpoint so the UI can flag expired/invalid keys.
// Providers without a known recipe are reported as "unchecked" (never guessed).

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// keyRecipe builds the validation request for a provider from the stored value,
// and decides whether an HTTP status means the key is valid.
type keyRecipe struct {
	build func(val string) *http.Request
	valid func(code int) bool
}

func httpOK(c int) bool { return c == 200 }

func getReq(u string, headers ...[2]string) *http.Request {
	r, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil
	}
	for _, h := range headers {
		r.Header.Set(h[0], h[1])
	}
	return r
}

// postReq / colon helpers for recipes that POST or carry "a:b" values.
func postReq(u string, headers ...[2]string) *http.Request {
	r, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return nil
	}
	for _, h := range headers {
		r.Header.Set(h[0], h[1])
	}
	return r
}
func beforeColon(v string) string {
	if i := strings.Index(v, ":"); i >= 0 {
		return v[:i]
	}
	return v
}
func afterColon(v string) string {
	if i := strings.Index(v, ":"); i >= 0 {
		return v[i+1:]
	}
	return v
}

// keyCheckRecipes — validation endpoints verified live against real keys.
// Conservative: a wrong recipe would flag a good key as expired.
var keyCheckRecipes = map[string]keyRecipe{
	"shodan":         {build: func(v string) *http.Request { return getReq("https://api.shodan.io/api-info?key=" + url.QueryEscape(v)) }, valid: httpOK},
	"github":         {build: func(v string) *http.Request { return getReq("https://api.github.com/rate_limit", [2]string{"Authorization", "Bearer " + v}, [2]string{"Accept", "application/vnd.github+json"}) }, valid: httpOK},
	"securitytrails": {build: func(v string) *http.Request { return getReq("https://api.securitytrails.com/v1/ping", [2]string{"APIKEY", v}) }, valid: httpOK},
	"virustotal":     {build: func(v string) *http.Request { return getReq("https://www.virustotal.com/api/v3/domains/google.com", [2]string{"x-apikey", v}) }, valid: httpOK},
	"censys":         {build: func(v string) *http.Request { return getReq("https://api.platform.censys.io/v3/global/asset/host/8.8.8.8", [2]string{"Authorization", "Bearer " + afterColon(v)}) }, valid: httpOK},
	"urlscan":        {build: func(v string) *http.Request { return getReq("https://urlscan.io/user/quotas/", [2]string{"API-Key", v}) }, valid: httpOK},
	"criminalip":     {build: func(v string) *http.Request { return postReq("https://api.criminalip.io/v1/user/me", [2]string{"x-api-key", v}) }, valid: httpOK},
	"hunter":         {build: func(v string) *http.Request { return getReq("https://api.hunter.io/v2/account?api_key=" + url.QueryEscape(v)) }, valid: httpOK},
	"binaryedge":     {build: func(v string) *http.Request { return getReq("https://api.binaryedge.io/v2/user/subscription", [2]string{"X-Key", v}) }, valid: httpOK},
	"netlas":         {build: func(v string) *http.Request { return getReq("https://app.netlas.io/api/users/current/", [2]string{"X-API-Key", v}) }, valid: httpOK},
	"intelx":         {build: func(v string) *http.Request { return getReq("https://free.intelx.io/authenticate/info", [2]string{"x-key", v}) }, valid: httpOK},
	"fullhunt":       {build: func(v string) *http.Request { return getReq("https://fullhunt.io/api/v1/auth/status", [2]string{"X-API-KEY", v}) }, valid: httpOK},
	"leakix":         {build: func(v string) *http.Request { return getReq("https://leakix.net/host/8.8.8.8", [2]string{"api-key", v}, [2]string{"Accept", "application/json"}) }, valid: httpOK},
	"certspotter":    {build: func(v string) *http.Request { return getReq("https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=false&expand=dns_names", [2]string{"Authorization", "Bearer " + v}) }, valid: httpOK},
	"whoisxmlapi":    {build: func(v string) *http.Request { return getReq("https://user.whoisxmlapi.com/service/account-balance?output_format=JSON&apiKey=" + url.QueryEscape(v)) }, valid: httpOK},
	"fofa":           {build: func(v string) *http.Request { return getReq("https://fofa.info/api/v1/info/my?email=" + url.QueryEscape(beforeColon(v)) + "&key=" + url.QueryEscape(afterColon(v))) }, valid: httpOK},
	"bevigil":        {build: func(v string) *http.Request { return getReq("https://osint.bevigil.com/api/example.com/subdomains/", [2]string{"X-Access-Token", v}) }, valid: httpOK},
}

// handleKeyCheck validates every configured key concurrently and returns, per
// provider: status ("valid"|"invalid"|"error"|"unchecked"), the HTTP code, and a
// short detail. "invalid" means the provider answered but rejected the key
// (likely expired/wrong); "error" means we couldn't reach it (network/timeout).
func (s *Server) handleKeyCheck(w http.ResponseWriter, r *http.Request) {
	keys, err := s.St.ListKeys()
	if err != nil {
		writeDetail(w, 500, err.Error())
		return
	}

	type result struct {
		Provider string `json:"provider"`
		Status   string `json:"status"`
		Code     int    `json:"http_code"`
		Detail   string `json:"detail"`
	}

	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 12 * time.Second}

	var (
		mu   sync.Mutex
		out  = []result{}
		wg   sync.WaitGroup
		sem  = make(chan struct{}, 6) // cap concurrency
	)

	for _, k := range keys {
		if strings.TrimSpace(k.Value) == "" {
			continue
		}
		recipe, ok := keyCheckRecipes[k.Provider]
		if !ok {
			mu.Lock()
			out = append(out, result{Provider: k.Provider, Status: "unchecked", Detail: "no validation recipe for this provider"})
			mu.Unlock()
			continue
		}
		wg.Add(1)
		go func(provider, value string, rec keyRecipe) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req := rec.build(value)
			if req == nil {
				mu.Lock()
				out = append(out, result{Provider: provider, Status: "error", Detail: "bad request"})
				mu.Unlock()
				return
			}
			resp, err := client.Do(req.WithContext(ctx))
			if err != nil {
				mu.Lock()
				out = append(out, result{Provider: provider, Status: "error", Detail: "unreachable: " + err.Error()})
				mu.Unlock()
				return
			}
			_ = resp.Body.Close()
			res := result{Provider: provider, Code: resp.StatusCode}
			switch {
			case rec.valid(resp.StatusCode):
				res.Status = "valid"
				res.Detail = "ok"
			case resp.StatusCode == 401 || resp.StatusCode == 403:
				res.Status = "invalid"
				res.Detail = "rejected (expired or wrong key)"
			case resp.StatusCode == 429:
				res.Status = "valid"
				res.Detail = "rate-limited but authenticated"
			default:
				res.Status = "error"
				res.Detail = "unexpected status"
			}
			mu.Lock()
			out = append(out, res)
			mu.Unlock()
		}(k.Provider, k.Value, recipe)
	}
	wg.Wait()

	writeJSON(w, 200, map[string]any{"items": out, "checked_at": iso(time.Now())})
}
