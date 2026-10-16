package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/Autumn-27/artex/k1z/store"
)

// provider mirrors the 31-entry PROVIDERS catalogue in routes/keys.py.
type provider struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	URL       string `json:"url"`
	Hint      string `json:"hint"`
	Subfinder bool   `json:"subfinder"`
	Uncover   *bool  `json:"uncover,omitempty"`
	EnvVar    string `json:"env_var"`
}

func ub() *bool { b := true; return &b }
func fb() *bool { b := false; return &b }

var providers = []provider{
	{"shodan", "Shodan", "Internet Scanner", "shodan.io", "API key from account.shodan.io", true, ub(), "SHODAN_API_KEY"},
	{"censys", "Censys", "Internet Scanner", "censys.com", "API_ID:API_SECRET", true, ub(), "CENSYS_API_ID"},
	{"fofa", "FOFA", "Internet Scanner", "en.fofa.info", "email@example.com:API_KEY", true, ub(), "FOFA_KEY"},
	{"zoomeye", "ZoomEye", "Internet Scanner", "zoomeye.hk", "API key (subfinder key: zoomeyeapi)", true, ub(), "ZOOMEYE_API_KEY"},
	{"quake", "Quake (360)", "Internet Scanner", "quake.360.cn", "API token", false, ub(), "QUAKE_API_KEY"},
	{"binaryedge", "BinaryEdge", "Internet Scanner", "binaryedge.io", "API key (uncover only — removed from subfinder v2.14)", false, ub(), "BINARYEDGE_API_KEY"},
	{"netlas", "Netlas", "Internet Scanner", "netlas.io", "API key", true, ub(), "NETLAS_API_KEY"},
	{"fullhunt", "FullHunt", "Internet Scanner", "fullhunt.io", "API key (env only — not in current subfinder build)", false, fb(), "FULLHUNT_API_KEY"},
	{"leakix", "LeakIX", "Internet Scanner", "leakix.net", "API key", true, fb(), "LEAKIX_API_KEY"},
	{"hunter", "Hunter.io", "Internet Scanner", "hunter.io", "API key — uncover host/domain search (free tier available)", false, ub(), "HUNTER_API_KEY"},
	{"criminalip", "CriminalIP", "Internet Scanner", "criminalip.io", "API key — uncover internet scanner (free tier available)", false, ub(), "CRIMINALIP_API_KEY"},
	{"greynoise", "GreyNoise", "Internet Scanner", "greynoise.io", "API key — uncover internet noise scanner", false, ub(), "GREYNOISE_API_KEY"},
	{"chaos", "Chaos (PD)", "Subdomain Intel", "chaos.projectdiscovery.io", "API key — auto-injected as $CHAOS_API_KEY env var", true, nil, "CHAOS_API_KEY"},
	{"securitytrails", "SecurityTrails", "Subdomain Intel", "securitytrails.com", "API key — auto-injected as $SECURITYTRAILS_KEY env var", true, nil, "SECURITYTRAILS_KEY"},
	{"virustotal", "VirusTotal", "Subdomain Intel", "virustotal.com", "API key — auto-injected as $VIRUSTOTAL_KEY env var", true, nil, "VIRUSTOTAL_KEY"},
	{"bevigil", "BeVigil", "Subdomain Intel", "bevigil.com", "API key — auto-injected as $BEVIGIL_KEY env var", true, nil, "BEVIGIL_KEY"},
	{"c99", "C99", "Subdomain Intel", "subdomainfinder.c99.nl", "API key", true, nil, "C99_API_KEY"},
	{"intelx", "IntelX", "Subdomain Intel", "intelx.io", "API key only (UUID) — host suffix :2.intelx.io auto-appended for subfinder", true, nil, "INTELX_API_KEY"},
	{"hackertarget", "HackerTarget", "Subdomain Intel", "hackertarget.com", "API key", true, nil, "HACKERTARGET_API_KEY"},
	{"dnsdumpster", "DNSDumpster", "Subdomain Intel", "dnsdumpster.com", "API key", true, nil, "DNSDUMPSTER_API_KEY"},
	{"whoisxmlapi", "WhoisXML", "Subdomain Intel", "whoisxmlapi.com", "API key", true, nil, "WHOISXMLAPI_API_KEY"},
	{"urlscan", "URLScan.io", "Archive / Cert", "urlscan.io", "API key", true, nil, "URLSCAN_API_KEY"},
	{"certspotter", "CertSpotter", "Archive / Cert", "sslmate.com/certspotter", "API key", true, nil, "CERTSPOTTER_API_KEY"},
	{"github", "GitHub Token", "Archive / Cert", "github.com", "ghp_xxxxxxxxxxxx — subfinder + gau + github code search", true, nil, "GITHUB_TOKEN"},
	{"google_cse", "Google CSE API Key", "Search & Dork", "console.cloud.google.com", "AIzaSy... — Custom Search API key", false, nil, "GOOGLE_CSE_KEY"},
	{"google_cx", "Google Search Engine ID", "Search & Dork", "programmablesearchengine.google.com", "CX ID", false, nil, "GOOGLE_CX"},
	{"qwen", "Qwen (DashScope)", "AI Assistant", "dashscope.aliyuncs.com", "sk-... — DashScope API key for Qwen AI terminal", false, nil, "DASHSCOPE_API_KEY"},
}

func providerByID(id string) *provider {
	for i := range providers {
		if providers[i].ID == id {
			return &providers[i]
		}
	}
	return nil
}

func maskValue(v string) string {
	if len(v) > 4 {
		return strings.Repeat("*", len(v)-4) + v[len(v)-4:]
	}
	return "****"
}

func (s *Server) handleKeyProviders(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, providers)
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	keys, _ := s.St.ListKeys()
	byID := map[string]store.ApiKey{}
	for _, k := range keys {
		byID[k.Provider] = k
	}
	out := []map[string]any{}
	for _, p := range providers {
		if k, ok := byID[p.ID]; ok {
			out = append(out, map[string]any{
				"provider": p.ID, "masked": maskValue(k.Value), "configured": true,
				"updated_at": iso(k.UpdatedAt), "meta": p,
			})
		} else {
			out = append(out, map[string]any{
				"provider": p.ID, "masked": nil, "configured": false,
				"updated_at": nil, "meta": p,
			})
		}
	}
	writeJSON(w, 200, out)
}

func (s *Server) handleKeyStats(w http.ResponseWriter, r *http.Request) {
	keys, _ := s.St.ListKeys()
	writeJSON(w, 200, map[string]any{"configured": len(keys), "total": len(providers)})
}

func (s *Server) handlePutKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	if providerByID(id) == nil {
		writeDetail(w, 400, "Unknown provider: '"+id+"'")
		return
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := readJSON(r, &body); err != nil {
		writeDetail(w, 422, err.Error())
		return
	}
	if strings.TrimSpace(body.Value) == "" {
		writeDetail(w, 422, "Key value cannot be empty")
		return
	}
	if err := s.St.UpsertKey(id, strings.TrimSpace(body.Value)); err != nil {
		writeDetail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"provider": id, "masked": maskValue(body.Value), "configured": true,
		"updated_at": iso(store.NowUTC()),
	})
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	if providerByID(id) == nil {
		writeDetail(w, 400, "Unknown provider: '"+id+"'")
		return
	}
	_ = s.St.DeleteKey(id)
	w.WriteHeader(204)
}

func (s *Server) handleKeyExportSubfinder(w http.ResponseWriter, r *http.Request) {
	keys, _ := s.St.ListKeys()
	byID := map[string]string{}
	for _, k := range keys {
		byID[k.Provider] = k.Value
	}
	var b strings.Builder
	for _, p := range providers {
		if !p.Subfinder {
			continue
		}
		if v, ok := byID[p.ID]; ok && v != "" {
			key := p.ID
			if p.ID == "zoomeye" {
				key = "zoomeyeapi"
			}
			val := maskValue(v) // masked preview — never expose raw keys
			if p.ID == "intelx" && !strings.Contains(v, ":") {
				val = maskValue(v) + ":2.intelx.io"
			}
			b.WriteString(key + ":\n  - " + val + "\n")
		}
	}
	text := b.String()
	if text == "" {
		text = "# no keys configured"
	}
	writeJSON(w, 200, map[string]any{"yaml": text})
}

func (s *Server) handleKeyEnvStatus(w http.ResponseWriter, r *http.Request) {
	keys, _ := s.St.ListKeys()
	byID := map[string]string{}
	for _, k := range keys {
		byID[k.Provider] = k.Value
	}
	out := []map[string]any{}
	for _, p := range providers {
		envVal := ""
		if v, ok := os.LookupEnv(p.EnvVar); ok {
			envVal = v
		}
		if p.ID == "censys" {
			envVal = os.Getenv("CENSYS_API_ID") + ":" + os.Getenv("CENSYS_API_SECRET")
		}
		dbVal := byID[p.ID]
		source := "none"
		if dbVal != "" && envVal != "" {
			source = "both"
		} else if dbVal != "" {
			source = "db"
		} else if envVal != "" {
			source = "env"
		}
		conflict := source == "both" && dbVal != envVal
		out = append(out, map[string]any{
			"provider": p.ID, "env_var": p.EnvVar, "source": source,
			"conflict": conflict, "active": source != "none",
		})
	}
	writeJSON(w, 200, out)
}
