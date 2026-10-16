// Package schedule is the cron scheduler (replaces Celery beat): a minute
// ticker launches due schedules, and daily maintenance jobs run workspace
// cleanup (02:00), tool version checks (04:00) and nuclei template updates
// (04:30). The last tick is exposed for /health.
package schedule

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/runner"
	"github.com/Autumn-27/artex/k1z/store"
	"github.com/Autumn-27/artex/k1z/toolsmeta"
)

var lastTick atomic.Value // string

// LastTick returns the ISO timestamp of the last scheduler tick ("" before first).
func LastTick() string {
	if v, ok := lastTick.Load().(string); ok {
		return v
	}
	return ""
}

// Start runs the minute ticker until ctx is cancelled.
func Start(ctx context.Context, st *store.Store, r *runner.Runner) {
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		Tick(st, r) // fire immediately on boot
		lastTick.Store(store.FmtTime(store.NowUTC()))
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lastTick.Store(store.FmtTime(store.NowUTC()))
				Tick(st, r)
				dailyJobs(st)
			}
		}
	}()
}

// Tick launches every due schedule (local time) and advances next_run_at.
func Tick(st *store.Store, r *runner.Runner) {
	now := time.Now()
	due, err := st.DueSchedules(now)
	if err != nil {
		return
	}
	for _, sc := range due {
		run, err := r.Launch(runner.LaunchInput{
			Workflow:       sc.Workflow,
			Target:         sc.Target,
			Vars:           varsMap(sc.VarsJSON),
			SkipScopeCheck: true, // parity: schedule trigger path skips the gate
		})
		if err != nil {
			log.Printf("[schedule] launch %s: %v", sc.Name, err)
		} else {
			sc.LastRunID = &run.ID
			t := store.NowUTC()
			sc.LastRunAt = t
		}
		// always advance (no hot retry loop), local time like croniter
		if next := NextAfter(sc.CronExpr, now); !next.IsZero() {
			sc.NextRunAt = next
		}
		_ = st.UpdateSchedule(sc)
	}
}

// ── daily maintenance (replaces Celery beat entries) ─────────────────────────

// workspace keep-list from tasks.py workspace_cleanup.
var cleanupKeep = map[string]bool{
	"subdomains.txt": true, "subdomains_resolved.txt": true, "subzy.txt": true,
	"nuclei.jsonl": true, "nuclei_urls.jsonl": true, "httpx.jsonl": true,
	"naabu.jsonl": true, "katana.jsonl": true, "gau.jsonl": true,
	"waybackurls.txt": true, "afrog.jsonl": true, "urls_all.txt": true,
	"urls_params.txt": true, "kiterunner.txt": true, "resume.json": true,
}

const dailySettingKey = "maintenance_last_run_date"

// dailyJobs fires each maintenance job once per local calendar day.
func dailyJobs(st *store.Store) {
	today := time.Now().Format("2006-01-02")
	if v, _ := getSetting(dailySettingKey); v == today {
		return
	}
	_ = setSetting(dailySettingKey, today)

	now := time.Now()
	// 02:00 workspace cleanup — once per day, first tick after midnight
	go workspaceCleanup(st)
	// 04:00 tool version check — after 04:00
	if now.Hour() >= 4 {
		go toolsmeta.CheckVersions(st)
	}
	// 04:30 nuclei template update — after 04:30
	if now.Hour() > 4 || (now.Hour() == 4 && now.Minute() >= 30) {
		go toolsmeta.NucleiTemplateUpdate()
	}
}

// workspaceCleanup deletes transient files from terminal runs older than 30
// days, keeping the canonical result files and the screenshots directory.
func workspaceCleanup(st *store.Store) {
	runs, err := st.TerminalRunsFinishedBefore(time.Now().Add(-30 * 24 * time.Hour))
	if err != nil {
		return
	}
	var freed int64
	for _, run := range runs {
		if run.Workspace == "" {
			continue
		}
		n, err := cleanWorkspace(run.Workspace)
		if err != nil {
			continue
		}
		freed += n
	}
	if freed > 0 {
		log.Printf("[maintenance] workspace cleanup freed %d bytes", freed)
	}
}

func cleanWorkspace(ws string) (int64, error) {
	var freed int64
	entries, err := os.ReadDir(ws)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			if name == "screenshots" || name == "report" || strings.HasPrefix(name, ".") {
				continue
			}
			n, _ := dirSize(filepath.Join(ws, name))
			if err := os.RemoveAll(filepath.Join(ws, name)); err == nil {
				freed += n
			}
			continue
		}
		if cleanupKeep[name] || strings.HasPrefix(name, ".") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			freed += fi.Size()
			_ = os.Remove(filepath.Join(ws, name))
		}
	}
	return freed, nil
}

func dirSize(path string) (int64, error) {
	var size int64
	filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, nil
}

// ── settings helpers (stored via tool_versions-adjacent settings table) ──────

func getSetting(key string) (string, error) {
	path := filepath.Join(config.RunsDir(), "."+key)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func setSetting(key, value string) error {
	return os.WriteFile(filepath.Join(config.RunsDir(), "."+key), []byte(value), 0o644)
}

func varsMap(js string) map[string]string {
	m := map[string]string{}
	if js != "" {
		_ = json.Unmarshal([]byte(js), &m)
	}
	return m
}

// NextAfter computes the next fire time after t (5-field cron, local time).
func NextAfter(expr string, t time.Time) time.Time {
	p := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	sched, err := p.Parse(expr)
	if err != nil {
		return time.Time{}
	}
	return sched.Next(t)
}

// Valid checks a 5-field cron expression.
func Valid(expr string) bool {
	p := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	_, err := p.Parse(expr)
	return err == nil
}

var _ = sort.Strings
