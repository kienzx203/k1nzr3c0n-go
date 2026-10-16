package api

import (
	"encoding/json"
	"time"

	"k1nzr3c0n/internal/store"
)

// iso serializes like Python datetime.isoformat() or null.
func iso(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return store.FmtTime(t)
}

// ── run ──────────────────────────────────────────────────────────────────────

type runJSON struct {
	ID              string          `json:"id"`
	Workflow        string          `json:"workflow"`
	Target          string          `json:"target"`
	Status          string          `json:"status"`
	Workspace       string          `json:"workspace"`
	Vars            json.RawMessage `json:"vars"`
	ContinueOnError bool            `json:"continue_on_error"`
	Resume          bool            `json:"resume"`
	Returncode      *int            `json:"returncode"`
	ErrorMessage    *string         `json:"error_message"`
	Steps           json.RawMessage `json:"steps"`
	CreatedAt       any             `json:"created_at"`
	StartedAt       any             `json:"started_at"`
	FinishedAt      any             `json:"finished_at"`
	PausedAt        any             `json:"paused_at"`
}

func rawOr(js string, def string) json.RawMessage {
	if js == "" {
		return json.RawMessage(def)
	}
	return json.RawMessage(js)
}

func runToDict(r *store.Run) *runJSON {
	return &runJSON{
		ID: r.ID, Workflow: r.Workflow, Target: r.Target, Status: r.Status,
		Workspace: r.Workspace, Vars: rawOr(r.VarsJSON, "{}"),
		ContinueOnError: r.ContinueOnError, Resume: r.Resume,
		Returncode: r.Returncode, ErrorMessage: r.ErrorMessage,
		Steps:     rawOr(r.StepsJSON, "[]"),
		CreatedAt: iso(r.CreatedAt), StartedAt: iso(r.StartedAt),
		FinishedAt: iso(r.FinishedAt), PausedAt: iso(r.PausedAt),
	}
}

// ── finding ──────────────────────────────────────────────────────────────────

type findingJSON struct {
	ID          int64           `json:"id"`
	RunID       string          `json:"run_id"`
	Kind        string          `json:"kind"`
	Severity    *string         `json:"severity"`
	Host        string          `json:"host"`
	IP          *string         `json:"ip"`
	Port        *int            `json:"port"`
	Protocol    *string         `json:"protocol"`
	Name        *string         `json:"name"`
	TemplateID  *string         `json:"template_id"`
	URL         *string         `json:"url"`
	Title       *string         `json:"title"`
	Tech        json.RawMessage `json:"tech"`
	Evidence    *string         `json:"evidence"`
	Description *string         `json:"description"`
	Status      string          `json:"status"`
	Notes       *string         `json:"notes"`
	Tags        json.RawMessage `json:"tags"`
	CreatedAt   any             `json:"created_at"`
}

func findingToDict(f *store.Finding) *findingJSON {
	return &findingJSON{
		ID: f.ID, RunID: f.RunID, Kind: f.Kind, Severity: f.Severity, Host: f.Host,
		IP: f.IP, Port: f.Port, Protocol: f.Protocol, Name: f.Name,
		TemplateID: f.TemplateID, URL: f.URL, Title: f.Title,
		Tech: rawOr(f.Tech, "[]"), Evidence: f.Evidence, Description: f.Description,
		Status: f.Status, Notes: f.Notes, Tags: rawOr(f.Tags, "[]"),
		CreatedAt: iso(f.CreatedAt),
	}
}

// ── schedule ─────────────────────────────────────────────────────────────────

type scheduleJSON struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`
	Workflow       string          `json:"workflow"`
	Target         string          `json:"target"`
	CronExpr       string          `json:"cron_expr"`
	Vars           json.RawMessage `json:"vars"`
	Enabled        bool            `json:"enabled"`
	AlertNewAssets bool            `json:"alert_new_assets"`
	LastRunID      *string         `json:"last_run_id"`
	LastRunAt      any             `json:"last_run_at"`
	NextRunAt      any             `json:"next_run_at"`
	CreatedAt      any             `json:"created_at"`
}

func scheduleToDict(sc *store.Schedule) *scheduleJSON {
	return &scheduleJSON{
		ID: sc.ID, Name: sc.Name, Workflow: sc.Workflow, Target: sc.Target,
		CronExpr: sc.CronExpr, Vars: rawOr(sc.VarsJSON, "{}"),
		Enabled: sc.Enabled, AlertNewAssets: sc.AlertNewAssets,
		LastRunID: sc.LastRunID, LastRunAt: iso(sc.LastRunAt),
		NextRunAt: iso(sc.NextRunAt), CreatedAt: iso(sc.CreatedAt),
	}
}

// ── target ───────────────────────────────────────────────────────────────────

type targetJSON struct {
	Name      string          `json:"name"`
	Scope     json.RawMessage `json:"scope"`
	Mode      string          `json:"mode"`
	Notes     *string         `json:"notes"`
	CreatedAt any             `json:"created_at"`
	UpdatedAt any             `json:"updated_at"`
}

func targetToDict(t *store.Target) *targetJSON {
	mode := t.Mode
	if mode == "" {
		mode = "bounty"
	}
	return &targetJSON{
		Name: t.Name, Scope: rawOr(t.ScopeJSON, "[]"), Mode: mode,
		Notes: t.Notes, CreatedAt: iso(t.CreatedAt), UpdatedAt: iso(t.UpdatedAt),
	}
}

// ── new asset ────────────────────────────────────────────────────────────────

type newAssetJSON struct {
	ID        int64   `json:"id"`
	RunID     string  `json:"run_id"`
	Target    string  `json:"target"`
	Host      string  `json:"host"`
	Kind      *string `json:"kind"`
	FirstSeen any     `json:"first_seen"`
}

func newAssetToDict(n store.NewAsset) newAssetJSON {
	return newAssetJSON{
		ID: n.ID, RunID: n.RunID, Target: n.Target, Host: n.Host,
		Kind: n.Kind, FirstSeen: iso(n.FirstSeen),
	}
}
