// Package api implements the HTTP server: REST endpoints under /api/v1
// (plus legacy /api aliases), WebSocket endpoints under /ws, static SPA
// serving, and bearer-token auth. Paths and payloads match the Python API.
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"k1nzr3c0n/internal/bus"
	"k1nzr3c0n/internal/capture"
	"k1nzr3c0n/internal/config"
	"k1nzr3c0n/internal/explore"
	"k1nzr3c0n/internal/runner"
	"k1nzr3c0n/internal/store"
)

type Server struct {
	St     *store.Store
	Bus    *bus.Bus
	Runner *runner.Runner
	Mux     *http.ServeMux
	Cap     *capture.Proxy   // recording proxy (nil = unavailable)
	Explore *explore.Manager // autonomous exploration engine (nil = unavailable)

	lastBeatTick string // health "beat" liveness

	chatMu      sync.Mutex                    // guards chatCancels
	chatCancels map[int64]context.CancelFunc  // in-flight chat turns by conversation id
}

// registerChatCancel records the cancel func for a running chat turn so a Stop
// request can abort it; clearChatCancel removes it when the turn ends.
func (s *Server) registerChatCancel(convID int64, cancel context.CancelFunc) {
	s.chatMu.Lock()
	if s.chatCancels == nil {
		s.chatCancels = map[int64]context.CancelFunc{}
	}
	s.chatCancels[convID] = cancel
	s.chatMu.Unlock()
}
func (s *Server) clearChatCancel(convID int64) {
	s.chatMu.Lock()
	delete(s.chatCancels, convID)
	s.chatMu.Unlock()
}
func (s *Server) cancelChat(convID int64) bool {
	s.chatMu.Lock()
	defer s.chatMu.Unlock()
	if c, ok := s.chatCancels[convID]; ok {
		c()
		delete(s.chatCancels, convID)
		return true
	}
	return false
}

func New(st *store.Store, b *bus.Bus, r *runner.Runner) *Server {
	s := &Server{St: st, Bus: b, Runner: r, Mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.auth(s.cors(s.Mux))
}

// ── middleware ───────────────────────────────────────────────────────────────

// auth replicates Python's TokenAuthMiddleware: /api/* needs a bearer token,
// /ws/* needs ?token=, health/auth-status paths are exempt.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := config.APIToken()
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/") {
			if strings.HasPrefix(path, "/api/v1/health") || strings.HasPrefix(path, "/api/v1/auth/status") {
				next.ServeHTTP(w, r)
				return
			}
			if r.Header.Get("Authorization") != "Bearer "+token {
				writeDetail(w, 401, "Unauthorized")
				return
			}
		}
		if strings.HasPrefix(path, "/ws/") {
			// websocket auth happens at upgrade time (needs close code 4001)
			if r.URL.Query().Get("token") != token {
				writeDetail(w, 401, "Unauthorized")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

type detail struct {
	Detail string `json:"detail"`
}

func writeDetail(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(detail{Detail: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}

// ordered helpers for maps that must serialize with stable key order
type orderedMap struct {
	keys []string
	m    map[string]any
}

func newOrdered() *orderedMap { return &orderedMap{m: map[string]any{}} }

func (o *orderedMap) set(k string, v any) *orderedMap {
	if _, has := o.m[k]; !has {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
	return o
}

func (o *orderedMap) MarshalJSON() ([]byte, error) {
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(o.m[k])
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// ── routing ──────────────────────────────────────────────────────────────────

func (s *Server) routes() {
	m := s.Mux

	// auth + health
	m.HandleFunc("GET /api/v1/auth/status", s.handleAuthStatus)
	m.HandleFunc("GET /api/v1/health", s.handleHealth)

	// runs (+ legacy /api aliases)
	for _, prefix := range []string{"/api/v1", "/api"} {
		m.HandleFunc("POST "+prefix+"/runs", s.handleCreateRun)
		m.HandleFunc("GET "+prefix+"/runs", s.handleListRuns)
		m.HandleFunc("GET "+prefix+"/runs/stats", s.handleRunStats)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}", s.handleGetRun)
		m.HandleFunc("DELETE "+prefix+"/runs/{run_id}", s.handleDeleteRun)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/logs", s.handleRunLogs)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/new-assets", s.handleRunNewAssets)
		m.HandleFunc("POST "+prefix+"/runs/{run_id}/cancel", s.handleRunCancel)
		m.HandleFunc("POST "+prefix+"/runs/{run_id}/pause", s.handleRunPause)
		m.HandleFunc("DELETE "+prefix+"/runs/{run_id}/pause", s.handleRunPauseCancel)
		m.HandleFunc("POST "+prefix+"/runs/{run_id}/resume", s.handleRunResume)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/findings", s.handleRunFindings)
		m.HandleFunc("POST "+prefix+"/runs/{run_id}/findings/reparse", s.handleRunReparse)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/screenshots", s.handleScreenshots)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/files", s.handleListFiles)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/files/{path...}", s.handleGetFile)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/report", s.handleReport)
		m.HandleFunc("GET "+prefix+"/runs/{run_id}/report-draft", s.handleReportDraft)
	}

	// workflows (+ aliases)
	for _, prefix := range []string{"/api/v1", "/api"} {
		m.HandleFunc("GET "+prefix+"/workflows", s.handleListWorkflows)
		m.HandleFunc("POST "+prefix+"/workflows/import", s.handleImportWorkflow)
		m.HandleFunc("GET "+prefix+"/workflows/{name}/download", s.handleWorkflowDownload)
		m.HandleFunc("GET "+prefix+"/workflows/{name}/history", s.handleWorkflowHistory)
		m.HandleFunc("GET "+prefix+"/workflows/{name}/history/{snapshot}", s.handleWorkflowSnapshot)
		m.HandleFunc("GET "+prefix+"/workflows/{name}", s.handleGetWorkflow)
		m.HandleFunc("PUT "+prefix+"/workflows/{name}", s.handlePutWorkflow)
		m.HandleFunc("DELETE "+prefix+"/workflows/{name}", s.handleDeleteWorkflow)
	}

	// findings
	m.HandleFunc("GET /api/v1/findings/stats", s.handleFindingStats)
	m.HandleFunc("GET /api/v1/findings/duplicates", s.handleDuplicates)
	m.HandleFunc("POST /api/v1/findings/duplicates/resolve", s.handleResolveDuplicates)
	m.HandleFunc("GET /api/v1/findings/{finding_id}", s.handleGetFinding)
	m.HandleFunc("PATCH /api/v1/findings/{finding_id}", s.handlePatchFinding)
	m.HandleFunc("GET /api/v1/findings", s.handleListFindings)

	// assets
	m.HandleFunc("GET /api/v1/assets/stats", s.handleAssetStats)
	m.HandleFunc("GET /api/v1/assets", s.handleListAssets)
	m.HandleFunc("DELETE /api/v1/assets", s.handleDeleteAsset)

	// schedules
	m.HandleFunc("GET /api/v1/schedules", s.handleListSchedules)
	m.HandleFunc("POST /api/v1/schedules", s.handleCreateSchedule)
	m.HandleFunc("GET /api/v1/schedules/{id}", s.handleGetSchedule)
	m.HandleFunc("PATCH /api/v1/schedules/{id}", s.handlePatchSchedule)
	m.HandleFunc("DELETE /api/v1/schedules/{id}", s.handleDeleteSchedule)
	m.HandleFunc("POST /api/v1/schedules/{id}/trigger", s.handleTriggerSchedule)

	// targets + scope
	m.HandleFunc("GET /api/v1/scope/check", s.handleScopeCheck)
	m.HandleFunc("GET /api/v1/targets", s.handleListTargets)
	m.HandleFunc("POST /api/v1/targets", s.handleCreateTarget)
	m.HandleFunc("GET /api/v1/targets/{name}/audit", s.handleTargetAudit)
	m.HandleFunc("GET /api/v1/targets/{name}/new-assets", s.handleTargetNewAssets)
	m.HandleFunc("GET /api/v1/targets/{name}", s.handleGetTarget)
	m.HandleFunc("PATCH /api/v1/targets/{name}", s.handlePatchTarget)
	m.HandleFunc("DELETE /api/v1/targets/{name}", s.handleDeleteTarget)

	// keys
	m.HandleFunc("GET /api/v1/keys/providers", s.handleKeyProviders)
	m.HandleFunc("GET /api/v1/keys/stats", s.handleKeyStats)
	m.HandleFunc("GET /api/v1/keys/export/subfinder", s.handleKeyExportSubfinder)
	m.HandleFunc("GET /api/v1/keys/env-status", s.handleKeyEnvStatus)
	m.HandleFunc("PUT /api/v1/keys/{provider}", s.handlePutKey)
	m.HandleFunc("DELETE /api/v1/keys/{provider}", s.handleDeleteKey)
	m.HandleFunc("GET /api/v1/keys", s.handleListKeys)

	// tools + upload
	m.HandleFunc("GET /api/v1/tools", s.handleListTools)
	m.HandleFunc("POST /api/v1/tools/check", s.handleToolsCheck)
	m.HandleFunc("POST /api/v1/tools/update", s.handleToolsUpdate)
	m.HandleFunc("GET /api/v1/wordlists", s.handleListWordlists)
	m.HandleFunc("POST /api/v1/wordlists", s.handleUploadWordlist)
	m.HandleFunc("DELETE /api/v1/wordlists/{name}", s.handleDeleteWordlist)
	m.HandleFunc("POST /api/v1/upload/workflow", s.handleUploadWorkflow)

	// network + system
	m.HandleFunc("GET /api/v1/network/check", s.handleNetworkCheck)
	m.HandleFunc("POST /api/v1/network/fix", s.handleNetworkFix)
	m.HandleFunc("GET /api/v1/system/usage", s.handleSystemUsage)
	m.HandleFunc("GET /api/v1/system/version", s.handleVersion)
	m.HandleFunc("GET /api/v1/system/update/check", s.handleUpdateCheck)
	m.HandleFunc("POST /api/v1/system/update", s.handleSelfUpdate)
	m.HandleFunc("GET /api/v1/system/backup", s.handleBackup)
	m.HandleFunc("POST /api/v1/system/reset", s.handleSystemReset)

	// websockets
	m.HandleFunc("GET /ws/runs/{run_id}", s.handleRunWS)
	m.HandleFunc("GET /ws/terminal/{session_id}", s.handleTerminalWS)

	// AI agent layer (ScopeWeaver integration)
	m.HandleFunc("GET /api/v1/llm", s.handleLLMList)
	m.HandleFunc("POST /api/v1/llm", s.handleLLMCreate)
	m.HandleFunc("DELETE /api/v1/llm/{id}", s.handleLLMDelete)
	m.HandleFunc("GET /api/v1/llm/usage", s.handleLLMUsage)
	m.HandleFunc("GET /api/v1/agent/conversations", s.handleConvList)
	m.HandleFunc("GET /api/v1/agent/conversations/{id}/messages", s.handleConvMessages)
	m.HandleFunc("DELETE /api/v1/agent/conversations/{id}", s.handleConvDelete)
	m.HandleFunc("PATCH /api/v1/agent/conversations/{id}", s.handleConvRename)
	m.HandleFunc("POST /api/v1/agent/conversations/{id}/pin", s.handleConvPin)
	m.HandleFunc("POST /api/v1/agent/conversations/delete/batch", s.handleConvDeleteBatch)
	m.HandleFunc("POST /api/v1/agent/conversations/{id}/stop", s.handleConvStop)
	m.HandleFunc("GET /api/v1/chat/mentions", s.handleChatMentions)
	m.HandleFunc("POST /api/v1/chat/upload", s.handleChatUpload)
	m.HandleFunc("POST /api/v1/agent/chat/stream", s.handleAgentChatStream)
	m.HandleFunc("POST /api/v1/agent/chat", s.handleAgentChat)
	m.HandleFunc("POST /api/v1/agent/autopilot", s.handleAutopilot)
	m.HandleFunc("GET /api/v1/companies", s.handleCompanyList)
	m.HandleFunc("POST /api/v1/companies", s.handleCompanyCreate)
	m.HandleFunc("GET /api/v1/graph/assets", s.handleGraphAssets)
	m.HandleFunc("POST /api/v1/graph/assets", s.handleGraphAssetCreate)
	m.HandleFunc("DELETE /api/v1/graph/assets/{id}", s.handleGraphAssetDelete)
	m.HandleFunc("GET /api/v1/traffic", s.handleTrafficList)
	m.HandleFunc("GET /api/v1/traffic/{id}", s.handleTrafficGet)
	m.HandleFunc("POST /api/v1/traffic/bind", s.handleTrafficBind)
	m.HandleFunc("GET /api/v1/traffic/rules", s.handleRulesList)
	m.HandleFunc("POST /api/v1/traffic/rules", s.handleRulesCreate)
	m.HandleFunc("DELETE /api/v1/traffic/rules/{id}", s.handleRulesDelete)
	m.HandleFunc("GET /api/v1/skills", s.handleSkillsList)
	m.HandleFunc("GET /api/v1/agent/prompt", s.handleAgentPrompt)
	m.HandleFunc("GET /api/v1/llm/usage/list", s.handleLLMUsageList)
	m.HandleFunc("GET /api/v1/workspace", s.handleWorkspaceList)
	m.HandleFunc("POST /api/v1/workspace", s.handleWorkspaceUpload)
	m.HandleFunc("GET /api/v1/workspace/{name}", s.handleWorkspaceDownload)
	m.HandleFunc("DELETE /api/v1/workspace/{name}", s.handleWorkspaceDelete)
	m.HandleFunc("GET /api/v1/notify/settings", s.handleNotifyGet)
	m.HandleFunc("PUT /api/v1/notify/settings", s.handleNotifyPut)
	m.HandleFunc("POST /api/v1/notify/test", s.handleNotifyTest)
	m.HandleFunc("GET /api/v1/system/logs", s.handleSystemLogs)
	m.HandleFunc("POST /api/v1/assets/sync/scopesentry", s.handleScopeSentrySync)
	m.HandleFunc("GET /api/v1/agent/rules", s.handleAgentRulesList)
	m.HandleFunc("POST /api/v1/agent/rules", s.handleAgentRulesCreate)
	m.HandleFunc("DELETE /api/v1/agent/rules/{id}", s.handleAgentRulesDelete)
	m.HandleFunc("GET /api/v1/agent/audit", s.handleAgentAudit)
	m.HandleFunc("GET /api/v1/graph/untested", s.handleUntestedAssets)
	m.HandleFunc("GET /api/v1/mcp", s.handleMCPList)
	m.HandleFunc("POST /api/v1/mcp", s.handleMCPCreate)
	m.HandleFunc("DELETE /api/v1/mcp/{id}", s.handleMCPDelete)
	m.HandleFunc("GET /api/v1/approvals", s.handleApprovalsList)
	m.HandleFunc("POST /api/v1/approvals/{id}/decide", s.handleApprovalDecide)
	m.HandleFunc("POST /api/v1/runs/{run_id}/ask", s.handleSideQuestion)
	m.HandleFunc("GET /api/v1/capture/status", s.handleCaptureStatus)
	m.HandleFunc("POST /api/v1/capture/toggle", s.handleCaptureToggle)
	m.HandleFunc("GET /api/v1/report/engagement", s.handleEngagementReport)

	// ── autonomous tasks (exploration engine) ──
	m.HandleFunc("GET /api/v1/tasks", s.handleTaskList)
	m.HandleFunc("POST /api/v1/tasks", s.handleTaskCreate)
	m.HandleFunc("GET /api/v1/tasks/{id}", s.handleTaskGet)
	m.HandleFunc("DELETE /api/v1/tasks/{id}", s.handleTaskDelete)
	m.HandleFunc("POST /api/v1/tasks/{id}/start", s.handleTaskStart)
	m.HandleFunc("POST /api/v1/tasks/{id}/pause", s.handleTaskPause)
	m.HandleFunc("POST /api/v1/tasks/{id}/stop", s.handleTaskStop)
	m.HandleFunc("GET /api/v1/tasks/{id}/graph", s.handleTaskGraph)
	m.HandleFunc("GET /api/v1/tasks/{id}/activity", s.handleTaskActivity)
	m.HandleFunc("GET /api/v1/tasks/{id}/coverage", s.handleTaskCoverage)
	m.HandleFunc("GET /api/v1/findings/{finding_id}/retests", s.handleRetestList)
	m.HandleFunc("POST /api/v1/findings/{finding_id}/retest", s.handleRetestStart)
	m.HandleFunc("POST /api/v1/tasks/{id}/message", s.handleTaskMessage)
	m.HandleFunc("GET /api/v1/tasks/{id}/questions", s.handleTaskQuestions)
	m.HandleFunc("GET /ws/tasks/{id}", s.handleTaskStream)
	// agent role configs
	m.HandleFunc("GET /api/v1/agent-configs", s.handleAgentConfigList)
	m.HandleFunc("PATCH /api/v1/agent-configs/{role}", s.handleAgentConfigUpdate)
	// side-questions (human-in-the-loop)
	m.HandleFunc("GET /api/v1/questions/pending", s.handleQuestionsPending)
	m.HandleFunc("POST /api/v1/questions/{qid}/answer", s.handleQuestionAnswer)
	m.HandleFunc("POST /api/v1/questions/{qid}/skip", s.handleQuestionSkip)
	// task categories / templates / archive
	m.HandleFunc("GET /api/v1/task-categories", s.handleCategoryList)
	m.HandleFunc("POST /api/v1/task-categories", s.handleCategoryCreate)
	m.HandleFunc("DELETE /api/v1/task-categories/{id}", s.handleCategoryDelete)
	m.HandleFunc("PATCH /api/v1/tasks/{id}/category", s.handleTaskSetCategory)
	m.HandleFunc("GET /api/v1/task-templates", s.handleTemplateList)
	m.HandleFunc("POST /api/v1/task-templates", s.handleTemplateCreate)
	m.HandleFunc("DELETE /api/v1/task-templates/{id}", s.handleTemplateDelete)
	m.HandleFunc("POST /api/v1/task-templates/{id}/launch", s.handleTemplateLaunch)
	m.HandleFunc("POST /api/v1/tasks/{id}/archive", s.handleTaskArchive)
	m.HandleFunc("POST /api/v1/tasks/{id}/restore", s.handleTaskRestore)
	// LLM network setting + ollama + approval detail + update rollback
	m.HandleFunc("GET /api/v1/settings/local-llm", s.handleLocalLLMGet)
	m.HandleFunc("PUT /api/v1/settings/local-llm", s.handleLocalLLMSet)
	m.HandleFunc("GET /api/v1/ollama/models", s.handleOllamaModels)
	m.HandleFunc("GET /api/v1/approvals/{id}", s.handleApprovalDetail)
	m.HandleFunc("POST /api/v1/system/update/rollback", s.handleUpdateRollback)

	// static SPA
	s.mountStatic(m)
}
