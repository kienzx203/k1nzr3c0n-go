package notify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Filter is the contract for the notification_channels.filter JSONB column: the
// filter conditions of a channel instance. All fields are optional, and the
// default is "no filtering" — which is exactly the fallback semantics for
// malformed config; see ParseFilter.
type Filter struct {
	// MinSeverity is the minimum severity threshold (low/medium/high/critical);
	// empty = no threshold set.
	MinSeverity string `json:"min_severity"`
	// TaskIDs / AssetIDs: an empty array means no restriction; a non-empty one
	// requires the event to intersect with it.
	TaskIDs  []int64 `json:"task_ids"`
	AssetIDs []int64 `json:"asset_ids"`
	// VulnClassInclude empty means accept everything; non-empty requires vulnclass
	// to match any one of the keywords.
	// VulnClassExclude excludes if any one keyword matches (exclude takes
	// precedence over include).
	// Matching is case-insensitive substring — safer than regex: a user's
	// mistyped regex won't silently break the channel.
	VulnClassInclude []string `json:"vulnclass_include"`
	VulnClassExclude []string `json:"vulnclass_exclude"`
	// OnStatusChange decides whether this channel receives vulnerability
	// status-change events (only meaningful in realtime mode).
	OnStatusChange bool `json:"on_status_change"`
}

// ParseFilter parses a channel's filter config.
//
// **Never returns an error.** This is a deliberate design choice: when the
// filter config is malformed it always degrades to the zero-value Filter
// (= no filtering = matches everything), because for a vulnerability
// notification system, **pushing one extra is far better than silently dropping
// a high-severity one**. Letting a parse failure become "don't push" would give
// the user a channel that looks configured but actually pushes nothing — the
// worst failure mode.
func ParseFilter(raw []byte) Filter {
	var f Filter
	if len(raw) == 0 {
		return f
	}
	// On a parse failure f stays at its zero value, i.e. no filtering.
	_ = json.Unmarshal(raw, &f)
	return f
}

// ValidMinSeverity reports whether s is a valid severity threshold (an empty
// string means no threshold is set).
func ValidMinSeverity(s string) bool {
	if s == "" {
		return true
	}
	_, ok := severityRank[s]
	return ok
}

// Validate checks the fields of the filter config whose **values are
// constrained**, called when saving a channel.
//
// Why it must be caught on write: Match's test for an unknown threshold is
// `rank >= 0`, which is always true — meaning that a single typo in min_severity
// ("hgih") makes the filter **silently stop working** and turn into "push
// everything". This is consistent with the package's "better to over-push than
// to miss" tradeoff (nothing is missed), but the consequence is that the user
// thinks they're doing severity-based pushing while actually flooding the group
// with every vulnerability, with no sign that they misconfigured it. This kind
// of "silent degradation" is exactly what should be caught at the entry point.
//
// Note that Validate is used only on the **write** path. The read path still
// uses ParseFilter's lenient semantics, so that bad values already present in
// historical data won't make the whole channel fail to load.
func (f Filter) Validate() error {
	if !ValidMinSeverity(f.MinSeverity) {
		return fmt.Errorf("invalid minimum severity %q, options: low / medium / high / critical, or leave empty for no limit", f.MinSeverity)
	}
	return nil
}

// Match decides whether an event should be delivered to a channel with the given
// filter conditions.
//
// **Never returns an error**, for the same reason as ParseFilter: any internal
// anomaly is treated as a match. Decision order: event type → severity threshold
// → task/asset scope → vulnerability type keywords.
func Match(f Filter, s Snapshot) bool {
	// Status-change events are received only by channels that explicitly enable
	// them. Off by default, because the vast majority of users expect "push" to
	// mean "a new vulnerability was found", not a running log of every status
	// transition.
	if s.Kind == EventFindingStatusChanged && !f.OnStatusChange {
		return false
	}
	if !AtLeast(s.Severity, f.MinSeverity) {
		return false
	}
	if len(f.TaskIDs) > 0 && !slices.Contains(f.TaskIDs, s.TaskID) {
		return false
	}
	if len(f.AssetIDs) > 0 && !intersectsInt(f.AssetIDs, s.AssetIDs) {
		return false
	}
	// Exclude takes precedence: matching any exclude keyword drops it, even if it
	// also matched the include list.
	if len(f.VulnClassExclude) > 0 && containsAnyFold(s.VulnClass, f.VulnClassExclude) {
		return false
	}
	if len(f.VulnClassInclude) > 0 && !containsAnyFold(s.VulnClass, f.VulnClassInclude) {
		return false
	}
	return true
}

func intersectsInt(a, b []int64) bool {
	// A linear scan is fine for small sets; both sides are on the order of "a few
	// dozen hand-picked by a person", so building a map costs more than it saves.
	for _, v := range b {
		if slices.Contains(a, v) {
			return true
		}
	}
	return false
}

// containsAnyFold reports whether s contains any of the keywords
// (case-insensitive).
func containsAnyFold(s string, keywords []string) bool {
	lower := strings.ToLower(s)
	for _, kw := range keywords {
		kw = strings.ToLower(strings.TrimSpace(kw))
		if kw != "" && strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
