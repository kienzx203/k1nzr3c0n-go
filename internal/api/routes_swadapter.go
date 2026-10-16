package api

import (
	"net/http"
	"strings"
)

// ScopeWeaver UI adapter: the embedded ScopeWeaver frontend calls /api/* (no
// /v1). These handlers answer the boot + core endpoints with ScopeWeaver-shaped
// responses backed by k1nzr3c0n's store, so its real UI renders live data.

func (s *Server) mountSWAdapter(m *http.ServeMux) {
	m.HandleFunc("GET /api/auth/status", s.swAuthStatus)
	m.HandleFunc("GET /api/health", s.swHealth)
	m.HandleFunc("GET /api/settings", s.swSettings)
	m.HandleFunc("GET /api/version", s.swVersion)
	m.HandleFunc("GET /api/update/check", s.swUpdateCheck)
	m.HandleFunc("GET /api/user/me", s.swUserMe)
	m.HandleFunc("GET /api/users", s.swUsers)
	// catch-all: any unimplemented /api/* returns a permissive empty shape so the
	// UI never receives HTML where it expects JSON (prevents hard crashes).
	m.HandleFunc("GET /api/{rest...}", s.swCatchAll)
	m.HandleFunc("POST /api/{rest...}", s.swCatchAll)
}

func (s *Server) swAuthStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"initialized": true})
}

func (s *Server) swUserMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"username": "k1nzr3c0n", "authenticated": true})
}

func (s *Server) swUsers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"users": []any{map[string]any{"username": "k1nzr3c0n"}}, "total": 1})
}

func (s *Server) swHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"status": "ok", "ok": true})
}

func (s *Server) swVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"version": BuildVersion, "name": "k1nzr3c0n"})
}

func (s *Server) swUpdateCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"update_available": false, "current": BuildVersion, "latest": BuildVersion})
}

func (s *Server) swSettings(w http.ResponseWriter, r *http.Request) {
	localOnly := s.St.GetSetting("local_only_llm", "0") == "1"
	writeJSON(w, 200, map[string]any{
		"language":           "en",
		"max_concurrent":     3,
		"local_only_llm":     localOnly,
		"proxy":              "",
		"capture_enabled":    s.Cap != nil && s.Cap.Enabled(),
		"version":            BuildVersion,
		"web_search_enabled": false,
		"constraints":        []any{},
	})
}

// swCatchAll returns an empty-but-safe payload for any endpoint not yet mapped.
func (s *Server) swCatchAll(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	// list-ish paths get an empty array wrapper; others get an empty object
	if isListPath(rest) {
		writeJSON(w, 200, map[string]any{"items": []any{}, "total": 0, "records": []any{}, "data": []any{}})
		return
	}
	writeJSON(w, 200, map[string]any{})
}

func isListPath(p string) bool {
	for _, kw := range []string{"tasks", "findings", "assets", "conversations", "agents", "skills", "commands",
		"logs", "records", "profiles", "rules", "pending", "history", "intents", "nodes", "activity",
		"companies", "notify", "mcp", "tools", "sessions", "list"} {
		if strings.Contains(p, kw) {
			return true
		}
	}
	return false
}
