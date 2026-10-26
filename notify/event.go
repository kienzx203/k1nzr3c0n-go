package notify

import "github.com/Autumn-27/artex/locale"

// Snapshot is the contract for the notification_events.snapshot JSONB column.
// The writer is the finding-persistence transaction in the db layer; the readers
// are the delivery engine and filter matching in the server layer. The
// definition lives in this package because it is a "notification domain" payload:
// the db only serializes it and does not understand the field meanings.
//
// Why vulnerability fields are stored redundantly instead of looked up again at
// render time: a vulnerability may later be renamed, re-graded, or have its
// status changed, while the pushed content should reflect the conclusion **at
// the time it happened** — a re-lookup would give the dangerously misleading
// "later changed to low". It also means fan-out and rendering don't have to JOIN
// the findings/tasks/assets tables.
type Snapshot struct {
	// Event type: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Non-empty only when kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is a single vulnerability to be pushed, for channel rendering.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets holds the resolved asset display names (e.g. domain/IP). It is
	// filled in by the server layer — this package never touches the database
	// and cannot obtain the names.
	Assets []string
	// DetailURL is the back-link to the vulnerability detail; empty means
	// public_base_url is not configured and it is omitted at render time.
	DetailURL string
	// Status-change events only; when both are non-empty it renders as
	// "Pending → Fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether the item is a status-change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the item's display title: the manually assigned name first,
// falling back to the vulnerability type vulnclass, and a placeholder when both
// are empty — it never emits an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(unnamed vulnerability)"
}

// Message is the complete content of a single channel send.
type Message struct {
	// Language selects the render language (locale.Lang); empty → server default.
	Language locale.Lang
	// Length 1 for a single push; a whole batch for a digest push.
	// An empty slice is invalid; the caller must guarantee at least one item.
	Items []Item
	// When Batch=true, rendered as a digest message (different title, with the
	// time window and item count).
	Batch bool
	// WindowMinutes is the digest period (minutes), used only when Batch=true for
	// the "last N minutes" wording. Deliberately passed in explicitly via config
	// rather than computed as time.Since at render time: keeping rendering
	// deterministic makes it testable.
	WindowMinutes int
	// HomeURL is the platform dashboard address (global public_base_url); empty
	// means no dashboard entry point is included.
	HomeURL string
}
