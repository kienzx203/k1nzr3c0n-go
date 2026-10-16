package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/Autumn-27/artex/k1z/bus"
)

// handleRunWS streams live logs/steps for a run (server → client only).
func (s *Server) handleRunWS(w http.ResponseWriter, r *http.Request) {
	runID := r.PathValue("run_id")
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	send := func(m bus.Message) bool {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		return conn.Write(ctx, websocket.MessageText, mustJSON(m)) == nil
	}

	run, err := s.St.GetRun(runID)
	if err != nil {
		send(bus.Message{Type: "done", Status: "not_found", Steps: json.RawMessage("[]")})
		return
	}
	totalLogs, _ := s.St.CountLogs(runID)
	if !send(bus.Message{Type: "log_meta", Total: totalLogs}) {
		return
	}
	if isTerminal(run.Status) {
		send(doneMsg(run.Status, run.StepsJSON))
		return
	}
	ch, cancel := s.Bus.Subscribe(runID)
	defer cancel()
	// race guard: the run may have finished between the DB read and subscribe
	if run2, err := s.St.GetRun(runID); err == nil && isTerminal(run2.Status) {
		send(doneMsg(run2.Status, run2.StepsJSON))
		return
	}
	for msg := range ch {
		if !send(msg) {
			return
		}
		if msg.Type == "done" {
			return
		}
	}
}

func doneMsg(status, stepsJSON string) bus.Message {
	return bus.Message{Type: "done", Status: status, Steps: json.RawMessage(orEmpty(stepsJSON, "[]"))}
}

func isTerminal(status string) bool {
	switch status {
	case "completed", "failed", "cancelled", "paused":
		return true
	}
	return false
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
