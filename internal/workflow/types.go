// Package workflow implements the K1NZR3C0N workflow engine: YAML loading with
// includes and validation, {var} templating, Kahn topological ordering with BFS
// level grouping, and the parallel executor with pause/resume/cancel semantics.
// Behavior mirrors the Python engine (workflow.py) step for step.
package workflow

import (
	"fmt"
	"regexp"
	"strings"
)

// WorkflowError is a fatal engine error (maps to Python WorkflowError, exit 2).
type WorkflowError struct{ Msg string }

func (e *WorkflowError) Error() string { return e.Msg }

func werrf(format string, args ...any) error {
	return &WorkflowError{Msg: fmt.Sprintf(format, args...)}
}

// PauseExitCode mirrors EX_TEMPFAIL used by the Python engine.
const PauseExitCode = 75

// ErrPaused is returned when the pause flag was honored between levels.
var ErrPaused = &WorkflowError{Msg: "paused"}

// ErrCancelled is returned when the cancel flag was honored.
var ErrCancelled = &WorkflowError{Msg: "cancelled"}

// Timeout is a parsed step timeout in (fractional) seconds.
type Timeout struct{ Seconds float64 }

// Require is one post-run artifact check.
type Require struct {
	Path     string
	MinBytes int64
}

// Child is one fanout sub-command.
type Child struct {
	ID           string
	Name         string
	Run          string
	When         *string
	Shell        bool
	Timeout      *Timeout
	Retries      int
	Optional     bool
	SkipIfExists bool
	Outputs      map[string]string
	Requires     []Require
	Env          map[string]string
	Cwd          *string
	Index        int
}

// Step is one normalized workflow step.
type Step struct {
	ID                   string
	Name                 string
	DependsOn            []string
	Run                  *string
	When                 *string
	Shell                bool
	Timeout              *Timeout
	Retries              int
	Optional             bool
	SkipIfExists         bool
	RunOnFailedDeps      bool
	Outputs              map[string]string
	Requires             []Require
	Env                  map[string]string
	Cwd                  *string
	Fanout               []*Child
	FanoutConcurrency    int
	FanoutTimeoutDefault *Timeout
	Index                int
}

// Workflow is a fully expanded, validated workflow.
type Workflow struct {
	Name        string
	Description string
	MaxParallel int // 0 = unlimited
	Vars        map[string]string
	Steps       []*Step
}

var safeTargetRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// SafeTarget sanitizes a scan target into a directory-safe name.
func SafeTarget(target string) string {
	return safeTargetRe.ReplaceAllString(target, "_")
}

// VarsMerge merges workflow defaults with CLI overrides (overrides win).
func VarsMerge(defs, overrides map[string]string) map[string]string {
	out := make(map[string]string, len(defs)+len(overrides))
	for k, v := range defs {
		out[k] = v
	}
	for k, v := range overrides {
		out[k] = v
	}
	return out
}

// ParseVarOverrides turns ["k=v", "k2=v2"] (and bare "k" → "") into a map.
func ParseVarOverrides(items []string) (map[string]string, error) {
	out := map[string]string{}
	for _, it := range items {
		if it == "" {
			continue
		}
		k, v, hasEq := strings.Cut(it, "=")
		if k == "" || !hasEq {
			return nil, werrf("Invalid --vars entry: %s", it)
		}
		out[k] = v
	}
	return out, nil
}
