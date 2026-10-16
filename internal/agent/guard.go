package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"k1nzr3c0n/internal/store"
)

// Gate evaluates agent tool calls against the rule engine (ScopeWeaver
// guard/intercept concept): allow → run; deny → blocked message; ask → park
// a pending approval and block until decided (or timeout → deny).
type gateVerdict int

const (
	gateAllow gateVerdict = iota
	gateDeny
)

// GateCheck returns (allow, denyMessage). For "ask" rules it blocks the
// calling goroutine until the user decides via the approvals API.
func GateCheck(st *store.Store, tool, args string) (bool, string) {
	rule, hit := st.MatchAgentRule(tool, args)
	if !hit {
		return true, ""
	}
	switch rule.Action {
	case "allow":
		return true, ""
	case "deny":
		return false, fmt.Sprintf("Tool call %q blocked by agent rule #%d (pattern %q). This is a platform governance control, not a target defense — choose a different approach within scope.", tool, rule.ID, rule.ToolPattern)
	case "ask":
		id, err := st.InsertPendingApproval("TOOL:"+tool, tool, summarizeArgs(args), args)
		if err != nil {
			return false, "approval system unavailable — call denied"
		}
		deadline := time.Now().Add(10 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(2 * time.Second)
			a, err := st.GetApproval(id)
			if err != nil || a.Decision == nil {
				continue
			}
			if *a.Decision == "approve" {
				return true, ""
			}
			return false, fmt.Sprintf("User denied tool call %q (approval #%d).", tool, id)
		}
		return false, fmt.Sprintf("Approval #%d timed out — tool call %q denied.", id, tool)
	}
	return true, ""
}

func summarizeArgs(args string) string {
	var m map[string]any
	if json.Unmarshal([]byte(args), &m) == nil {
		var parts []string
		for k, v := range m {
			s := fmt.Sprintf("%v", v)
			if len(s) > 40 {
				s = s[:40] + "…"
			}
			parts = append(parts, k+"="+s)
		}
		return strings.Join(parts, " ")
	}
	if len(args) > 60 {
		return args[:60] + "…"
	}
	return args
}

// SeedAgentRules inserts sensible defaults once (matching ScopeWeaver's
// built-in intercept rules spirit, adapted to our tool surface).
func SeedAgentRules(st *store.Store) {
	marker := filepath.Join(baseDir(), "runs", ".agent_rules_seeded")
	if _, err := os.Stat(marker); err == nil {
		return
	}
	// guardrail: never let the agent cancel runs without asking
	_ = st.CreateAgentRule("cancel_run", "", "ask")
	_ = os.WriteFile(marker, []byte("1"), 0o644)
}

// Audit records every tool call outcome.
func Audit(st *store.Store, tool, args, result string, blocked bool) {
	_ = st.InsertAgentAudit(tool, args, result, blocked)
}
