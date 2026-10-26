// Package notify implements the IM / email push channel adapter layer for
// vulnerability findings.
//
// Layering: this package is a **leaf package** that depends only on the
// standard library. It knows nothing about the database or the server. Channel
// configuration is passed in as map[string]any (matching the
// notification_channels.config JSONB column), and the content to push is passed
// in as a Message. The benefit of splitting it this way: the parts that are
// genuinely error-prone — signature computation, UTF-8 truncation, filter
// matching — can be unit-tested without PostgreSQL, and the host only needs to
// do the orchestration on the server side.
//
// Concurrency contract: Channel implementations must be **stateless**. A single
// Channel instance is reused concurrently across many channel configurations
// (even multiple bot instances of the same channel); all credentials are always
// passed in via the cfg parameter. Caching things like the webhook URL into the
// implementation's own fields is not allowed.
package notify

import "github.com/Autumn-27/artex/locale"

// Channel type identifiers. The values are also the valid set for
// notification_channels.kind, validated against a whitelist on the server side
// (same approach as findings.status — no DB CHECK, so new channels are easy to
// add later).
const (
	KindDingTalk = "dingtalk" // DingTalk custom bot
	KindFeishu   = "feishu"   // Feishu (incl. Lark) custom bot
	KindWeCom    = "wecom"    // WeCom group bot
	KindWebhook  = "webhook"  // generic Webhook: custom method/headers/JSON template
	KindTelegram = "telegram" // Telegram Bot API
	KindEmail    = "email"    // SMTP email
)

// Event types, matching notification_events.kind.
const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

// InitKind is the fallback value for an empty kind in the config.
const InitKind = KindDingTalk

// severityRank maps a vulnerability severity to a comparable ordinal. An unknown
// severity returns 0, so any min_severity setting keeps unknown severities out —
// when in doubt, don't push, to avoid false-positive spam.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns the severity's ordinal; an unknown severity returns 0.
func SeverityRank(severity string) int { return severityRank[severity] }

// SeverityLabel returns the severity name with an emoji, used for message titles
// and card accent colors. Unknown severities are echoed back as-is, not invented.
func SeverityLabel(severity string, lang ...locale.Lang) string {
	switch severity {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🔵 Low"
	default:
		return severity
	}
}

// StatusLabel translates a disposition status into a human-readable label, used
// in status-change messages.
func StatusLabel(status string) string {
	switch status {
	case "pending":
		return "Pending"
	case "in_progress":
		return "In Progress"
	case "confirmed":
		return "Confirmed"
	case "resolved":
		return "Resolved"
	case "fixed":
		return "Fixed"
	case "false_positive":
		return "False Positive"
	case "ignored":
		return "Ignored"
	case "duplicate":
		return "Duplicate"
	case "risk_accepted":
		return "Risk Accepted"
	default:
		return status
	}
}

// AtLeast reports whether severity reaches the min threshold. An empty min means
// no threshold is set, so everything passes. Note that an unknown severity has
// ordinal 0 and is rejected by any non-empty min (see the severityRank comment).
func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
