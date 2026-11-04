package server

import (
	"fmt"
	"github.com/Autumn-27/artex/locale"
	"net/http"

	"github.com/Autumn-27/artex/db"
)

type taskLLMResolution struct {
	ProfileID *int64 `json:"profile_id,omitempty"`
	Name      string `json:"name"`
	Format    string `json:"format"`
	Model     string `json:"model"`
	Source    string `json:"source"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

func (s *Server) resolutionFromProfile(p *db.LLMProfile, source string) taskLLMResolution {
	if p == nil {
		return taskLLMResolution{Source: source, Reason: "LLM profile does not exist"}
	}
	id := p.ID
	result := taskLLMResolution{
		ProfileID: &id,
		Name:      p.Name,
		Format:    p.Format,
		Model:     p.Model,
		Source:    source,
	}
	if p.APIKey == "" {
		result.Reason = "LLM profile has no API Key set"
		return result
	}
	if _, _, ok := s.providerForProfile(p.ID); !ok {
		result.Reason = "LLM profile format or parameters are invalid"
		return result
	}
	result.Available = true
	return result
}

// resolveTaskRoleLLM mirrors taskLLMRuntime.current without creating a provider:
// role Agent binding -> explicit task chain -> active/global environment config.
// Database failures are returned rather than represented as an unavailable model.
func (s *Server) resolveTaskRoleLLM(t *Task, agentKey string) (taskLLMResolution, error) {
	if s == nil || s.m == nil || s.m.pg == nil {
		return taskLLMResolution{}, fmt.Errorf("database unavailable")
	}
	if taskNum, perr := parseTaskID(t.ID); perr == nil {
		id, ok, err := s.m.pg.TaskRoleLLMProfile(taskNum, agentKey)
		if err != nil {
			return taskLLMResolution{}, fmt.Errorf("load task role LLM: %w", err)
		}
		if ok && id != 0 {
			p, err := s.m.pg.ProfileByID(id)
			if err != nil {
				return taskLLMResolution{}, fmt.Errorf("load task role LLM profile: %w", err)
			}
			if p != nil {
				if resolved := s.resolutionFromProfile(p, "task_role"); resolved.Available {
					return resolved, nil
				}
			}
		}
	}
	a, err := s.m.pg.GetAgentByKey(agentKey)
	if err != nil {
		return taskLLMResolution{}, fmt.Errorf("load agent %q: %w", agentKey, err)
	}
	if a != nil && a.LLMProfileID != nil {
		p, err := s.m.pg.ProfileByID(*a.LLMProfileID)
		if err != nil {
			return taskLLMResolution{}, fmt.Errorf("load agent LLM profile: %w", err)
		}
		if p != nil {
			resolved := s.resolutionFromProfile(p, "agent_binding")
			if resolved.Available {
				return resolved, nil
			}
		}
	}
	state := t.llmStateSnapshot()
	if len(state.ProfileIDs) > 0 {
		if state.ActiveID == nil {
			return taskLLMResolution{Source: "task_chain", Reason: "task LLM profile chain quota is exhausted"}, nil
		}
		p, err := s.m.pg.ProfileByID(*state.ActiveID)
		if err != nil {
			return taskLLMResolution{}, fmt.Errorf("load task LLM profile: %w", err)
		}
		return s.resolutionFromProfile(p, "task_chain"), nil
	}
	p, err := s.m.pg.ActiveProfile()
	if err != nil {
		return taskLLMResolution{}, fmt.Errorf("load global LLM profile: %w", err)
	}
	if p != nil {
		resolved := s.resolutionFromProfile(p, "global_profile")
		if resolved.Available {
			return resolved, nil
		}
	}
	s.cfgMu.Lock()
	on, name, cfg := s.llmOn, s.llmProf, s.llmCfg
	s.cfgMu.Unlock()
	if on {
		if name == "" {
			name = "global config"
		}
		return taskLLMResolution{
			Name: name, Format: cfg.Provider(), Model: cfg.Model,
			Source: "environment", Available: true,
		}, nil
	}
	return taskLLMResolution{Source: "global", Reason: "no available LLM profile"}, nil
}

// validTaskLLMRole reports whether a role string is a per-role override target.
func validTaskLLMRole(role string) bool {
	switch role {
	case "mainagent", "planner", "worker", "goals":
		return true
	}
	return false
}

// GET /api/tasks/{id}/llm/roles — current per-role LLM overrides for a task.
func (s *Server) getTaskRoleLLM(w http.ResponseWriter, r *http.Request) {
	id, ok := canonicalTaskID(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	taskNum, err := parseTaskID(id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	overrides, err := s.m.pg.TaskRoleLLMProfiles(taskNum)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"role_llm_profiles": overrides})
}

// PUT /api/tasks/{id}/llm/roles — set/clear per-role LLM overrides. Body:
// {"role_llm_profiles": {"mainagent": 3, "planner": null, "worker": 5}}.
// A null value clears that role's override; an omitted role is left unchanged.
func (s *Server) updateTaskRoleLLM(w http.ResponseWriter, r *http.Request) {
	id, ok := canonicalTaskID(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	taskNum, err := parseTaskID(id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid task id")
		return
	}
	var body struct {
		RoleLLMProfiles map[string]*int64 `json:"role_llm_profiles"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON: "+err.Error())
		return
	}
	for role, pid := range body.RoleLLMProfiles {
		if !validTaskLLMRole(role) {
			writeErr(w, 400, "invalid role: "+role)
			return
		}
		if pid != nil {
			if _, ok := s.loadProfileConfig(*pid); !ok {
				writeErr(w, 400, fmt.Sprintf("LLM profile #%d is missing or invalid", *pid))
				return
			}
		}
		if err := s.m.pg.SetTaskRoleLLMProfile(taskNum, role, pid); err != nil {
			writeErr(w, 500, err.Error())
			return
		}
	}
	overrides, err := s.m.pg.TaskRoleLLMProfiles(taskNum)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"role_llm_profiles": overrides})
}

func (s *Server) taskLLMResolutionHandler(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	roles := map[string]taskLLMResolution{}
	for responseKey, agentKey := range map[string]string{
		"mainagent": "mainagent",
		"planner":   "planner",
		"worker":    "worker",
	} {
		resolved, err := s.resolveTaskRoleLLM(t, agentKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		roles[responseKey] = resolved
	}
	writeJSON(w, http.StatusOK, roles)
}

// resolutionFromProfileForLanguage is the locale-explicit form of
// resolutionFromProfile (display strings follow the request language).
func (s *Server) resolutionFromProfileForLanguage(p *db.LLMProfile, source string, lang locale.Lang) taskLLMResolution {
	return s.resolutionFromProfile(p, source)
}
