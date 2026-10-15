// Package config resolves paths and settings from the environment, mirroring
// the Python project's config.py. K1NZR3C0N_BASE is the root of all state.
package config

import (
	"os"
	"path/filepath"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// BaseDir returns the absolute base directory (K1NZR3C0N_BASE, default ".").
func BaseDir() string {
	b := env("K1NZR3C0N_BASE", ".")
	if abs, err := filepath.Abs(b); err == nil {
		return abs
	}
	return b
}

func RunsDir() string      { return filepath.Join(BaseDir(), "runs") }
func DBPath() string       { return filepath.Join(RunsDir(), "k1nzr3c0n.db") }
func WorkflowsDir() string { return filepath.Join(BaseDir(), "workflows") }
func WordlistsDir() string { return filepath.Join(BaseDir(), "wordlists") }
func StaticDir() string    { return filepath.Join(BaseDir(), "static") }
func HistoryDir() string   { return filepath.Join(WorkflowsDir(), ".history") }

// WebhookURL returns the notification webhook ("" = disabled).
func WebhookURL() string { return os.Getenv("K1NZR3C0N_WEBHOOK_URL") }

// WebhookUsername is used for Slack-style webhooks only.
func WebhookUsername() string { return env("K1NZR3C0N_WEBHOOK_USERNAME", "k1nzr3c0n") }

// APIToken enables bearer auth when non-empty.
func APIToken() string { return os.Getenv("K1NZR3C0N_API_TOKEN") }

// HTTPAddr is the listen address of the API server.
func HTTPAddr() string { return env("K1NZR3C0N_ADDR", ":8000") }

// WorkerConcurrency is the number of runs executing simultaneously.
func WorkerConcurrency() int {
	n := 2
	if v := os.Getenv("K1NZR3C0N_WORKERS"); v != "" {
		if p, ok := atoiPositive(v); ok {
			n = p
		}
	}
	return n
}

// TaskTimeLimit caps a single run's wall clock (seconds); 0 = env default 43200.
func TaskTimeLimit() int {
	if v := os.Getenv("K1NZR3C0N_TASK_TIME_LIMIT"); v != "" {
		if p, ok := atoiPositive(v); ok {
			return p
		}
	}
	return 43200
}

func atoiPositive(s string) (int, bool) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return 0, false
		}
	}
	return n, n > 0
}
