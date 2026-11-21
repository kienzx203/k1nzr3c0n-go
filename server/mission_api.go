package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/agent"
)

// Mission-profile API: edit the per-mission agent brains (M5) and the per-task agent
// overrides (M4). The three missions are bugbounty / redteam / review-source; the agent
// keys are mainagent / planner / worker / goals.

var missionAgentKeys = map[string]bool{"mainagent": true, "planner": true, "worker": true, "goals": true}
var missionNames = map[string]bool{"bugbounty": true, "redteam": true, "review-source": true, "design-review": true, "android": true}

// pgEffectivePrompts handles GET /api/mission-prompts/effective?mission=X → the prompt
// that WOULD actually run for each agent under that mission, with its source. Precedence:
// mission brain > global prompt override > built-in default. Lets the New-Task "override
// agent brains" UI show the current prompt before the user overrides it.
func (s *Server) pgEffectivePrompts(w http.ResponseWriter, r *http.Request) {
	mission := strings.TrimSpace(r.URL.Query().Get("mission"))
	if mission == "" {
		mission = "bugbounty"
	}
	defaults := agent.BuiltinPromptSeeds()
	type eff struct {
		Body   string `json:"body"`
		Source string `json:"source"` // mission | global | default
	}
	out := map[string]eff{}
	for key := range missionAgentKeys {
		if b, ok := s.m.pg.MissionPrompt(mission, key); ok {
			out[key] = eff{Body: b, Source: "mission"}
			continue
		}
		if a, err := s.m.pg.GetAgentByKey(key); err == nil && a != nil {
			if b, err := s.m.pg.CurrentPrompt(a.ID); err == nil && b != "" {
				out[key] = eff{Body: b, Source: "global"}
				continue
			}
		}
		out[key] = eff{Body: defaults[key], Source: "default"}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"prompts": out})
}

// pgListMissionPrompts handles GET /api/mission-prompts → every stored mission brain.
func (s *Server) pgListMissionPrompts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.m.pg.ListMissionPrompts()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"prompts": rows})
}

// pgSaveMissionPrompt handles PUT /api/mission-prompts/{mission}/{agent} → set one brain.
func (s *Server) pgSaveMissionPrompt(w http.ResponseWriter, r *http.Request) {
	mission := strings.TrimSpace(r.PathValue("mission"))
	agent := strings.TrimSpace(r.PathValue("agent"))
	if !missionNames[mission] || !missionAgentKeys[agent] {
		writeErr(w, 400, "unknown mission or agent key")
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid body")
		return
	}
	if err := s.m.pg.SetMissionPrompt(mission, agent, req.Body); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pgTaskAgentPrompts handles GET /api/tasks/{id}/agent-prompts → the task's per-agent overrides.
func (s *Server) pgTaskAgentPrompts(w http.ResponseWriter, r *http.Request) {
	tid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad task id")
		return
	}
	out := map[string]string{}
	for key := range missionAgentKeys {
		if b, ok := s.m.pg.TaskAgentPrompt(tid, key); ok {
			out[key] = b
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"overrides": out})
}

// pgSaveTaskAgentPrompt handles PUT /api/tasks/{id}/agent-prompt/{agent} → override (empty body clears).
func (s *Server) pgSaveTaskAgentPrompt(w http.ResponseWriter, r *http.Request) {
	tid, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, 400, "bad task id")
		return
	}
	agent := strings.TrimSpace(r.PathValue("agent"))
	if !missionAgentKeys[agent] {
		writeErr(w, 400, "unknown agent key")
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "invalid body")
		return
	}
	if err := s.m.pg.SetTaskAgentPrompt(tid, agent, req.Body); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
