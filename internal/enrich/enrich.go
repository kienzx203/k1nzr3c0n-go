// Package enrich asynchronously completes asset records in the background —
// the ScopeWeaver "enrich" concept (DNS + HTTP completion). It resolves
// domain/subdomain assets to IPs and probes HTTP assets for status/title/server,
// writing results back into each asset's meta. Best-effort, bounded, additive.
package enrich

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"k1nzr3c0n/internal/store"
)

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Start launches the background enrich loop until ctx is cancelled.
func Start(ctx context.Context, st *store.Store) {
	go func() {
		client := &http.Client{
			Timeout:   8 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		run := func() {
			assets, err := st.ListAssetsForEnrich(40)
			if err != nil {
				return
			}
			for _, a := range assets {
				if ctx.Err() != nil {
					return
				}
				enrichOne(st, client, a)
			}
		}
		run() // first pass promptly
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

func enrichOne(st *store.Store, client *http.Client, a store.Asset) {
	meta := map[string]any{}
	_ = json.Unmarshal([]byte(a.Meta), &meta)

	switch a.Type {
	case "domain", "subdomain", "site":
		if ips, err := net.LookupHost(hostOf(a.Value)); err == nil && len(ips) > 0 {
			meta["ips"] = ips
			for _, ip := range ips {
				_ = st.UpsertAsset(&store.Asset{CompanyID: a.CompanyID, Type: "ip", Value: ip,
					Meta: `{"parent":"` + a.Value + `","enriched":true}`, Source: "dns-enrich"})
			}
		}
		probeHTTP(client, "http://"+hostOf(a.Value), meta)
	case "endpoint":
		probeHTTP(client, a.Value, meta)
	}

	meta["enriched"] = true
	if b, err := json.Marshal(meta); err == nil {
		_ = st.UpdateAssetMeta(a.ID, string(b))
	}
}

func probeHTTP(client *http.Client, url string, meta map[string]any) {
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "k1nzr3c0n-enrich/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	meta["status_code"] = resp.StatusCode
	if srv := resp.Header.Get("Server"); srv != "" {
		meta["server"] = srv
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if mt := titleRe.FindSubmatch(body); len(mt) == 2 {
		title := strings.TrimSpace(html(string(mt[1])))
		if len(title) > 200 {
			title = title[:200]
		}
		if title != "" {
			meta["title"] = title
		}
	}
}

func hostOf(v string) string {
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	if i := strings.IndexAny(v, "/:"); i >= 0 {
		v = v[:i]
	}
	return v
}

// html collapses a few common entities for readable titles.
func html(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "\n", " ", "\t", " ")
	return strings.Join(strings.Fields(r.Replace(s)), " ")
}
