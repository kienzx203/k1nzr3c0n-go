package notify

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// Channel is an adapter for a notification channel. Implementations must be **stateless**: the same
// instance is reused concurrently across many channel configs, and credentials are always passed in via the cfg parameter.
type Channel interface {
	// Kind returns the channel type identifier, which must match the key in the registry.
	Kind() string
	// Validate is called when saving config, checking required fields and format. The returned error
	// is shown directly to the person configuring it, so the wording should say "which field is
	// missing" rather than a vague "invalid config".
	Validate(cfg map[string]any) error
	// Send delivers one message, returning the **number of items actually delivered** and an error.
	//
	// Why return a count: every platform has a message length limit, and a digest message gets
	// truncated when it cannot hold the whole batch. If the caller unconditionally marks the whole
	// batch as delivered, the truncated items vanish — invisible in the message, and shown as
	// successful in the delivery history, with nowhere to discover that a vulnerability was never
	// sent. After kept is returned, the caller marks only the first kept items and leaves the rest for the next batch.
	//
	// A returned error means delivery failed, and a *PermanentError means it should not be retried.
	// On failure kept is meaningless and the caller should ignore it.
	Send(ctx context.Context, cfg map[string]any, m Message) (int, error)
	// DefaultRatePerMin returns the channel's officially recommended per-minute delivery limit, used
	// as the default rate limit when creating a new channel instance. Returns 0 when there is no known limit.
	DefaultRatePerMin() int
	// SecretKeys returns the key names in this channel's config that are credentials. When the API
	// echoes config, the values of these keys are masked, and on update a masked value means the
	// original value in the store is kept. Only the implementation itself knows which fields count as
	// credentials (WeCom's entire Webhook URL is a credential, whereas DingTalk's is only the secret
	// within it), so this knowledge must come from the channel and cannot be guessed by the layer above.
	SecretKeys() []string
	// DestinationKeys returns the key names in this channel's config that decide "where the message is sent".
	//
	// Like SecretKeys, this is security-related: the destination address and the credentials are two
	// independent sets of fields. If "change only the address, keep the credentials as-is" were
	// allowed, anyone who can edit the channel config could send the real credentials in the store to
	// a server they control, and the channel config's masking would lose all meaning.
	// See PrepareConfigUpdate for details.
	DestinationKeys() []string
}

// registry is the channel registry. Deliberately an explicit literal rather than init()
// self-registration: this way "which channels exist" can be seen in one place, and adding a channel
// exposes any omission at compile time rather than relying on a runtime side effect.
var registry = map[string]Channel{
	KindDingTalk: dingTalkChannel{},
	KindFeishu:   feishuChannel{},
	KindWeCom:    weComChannel{},
	KindWebhook:  webhookChannel{},
	KindTelegram: telegramChannel{},
	KindEmail:    emailChannel{},
}

// Get fetches a channel implementation by type.
func Get(kind string) (Channel, bool) {
	c, ok := registry[kind]
	return c, ok
}

// ValidKind reports whether kind is a supported channel type.
func ValidKind(kind string) bool {
	_, ok := registry[kind]
	return ok
}

// Kinds returns all supported channel types, sorted lexicographically (for stable display in UI dropdowns).
func Kinds() []string {
	out := make([]string, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// PermanentError marks a delivery failure that should not be retried: bad credentials, the
// destination rejecting it, an invalid request body, etc. Retrying is only meaningful for transient
// faults (network jitter, rate limiting, a 5xx from the peer); repeatedly backing off and retrying a
// permanent failure will neither succeed nor help, and it buries the real error in the retry log.
type PermanentError struct{ Err error }

func (e *PermanentError) Error() string { return e.Err.Error() }
func (e *PermanentError) Unwrap() error { return e.Err }

// Permanent marks err as a permanent failure. Returns nil when err is nil, which makes it convenient
// to write `return Permanent(someCheck())`.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &PermanentError{Err: err}
}

// IsPermanent reports whether the err chain carries a permanent-failure mark.
func IsPermanent(err error) bool {
	var pe *PermanentError
	return errors.As(err, &pe)
}

// ---- config-reading helpers ----
//
// Channel config comes from a JSONB column in the database; after encoding/json deserialization it
// is a map[string]any, where numbers are always float64 and arrays are []any. The helpers below
// unify this conversion layer and tolerate the type drift caused by users leaving fields blank in
// the UI (such as entering the port as a string).

// cfgString reads a string config item, trimming leading and trailing whitespace — it is easy to pick up when copy-pasting from a web form.
func cfgString(cfg map[string]any, key string) string {
	v, ok := cfg[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// cfgInt reads an integer config item, accepting both float64 (JSON's default) and string sources.
func cfgInt(cfg map[string]any, key string) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// cfgBool reads a boolean config item, accepting the strings "true"/"1".
func cfgBool(cfg map[string]any, key string) bool {
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "true" || s == "1" || s == "yes"
	default:
		return false
	}
}

// cfgStrings reads a string-array config item, auto-trimming whitespace and discarding empty strings.
func cfgStrings(cfg map[string]any, key string) []string {
	raw, ok := cfg[key].([]any)
	if !ok {
		// Also accepts a single string, convenient for a form submission with only one value.
		if s := cfgString(cfg, key); s != "" {
			return []string{s}
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cfgMap reads a string-map config item (such as custom HTTP headers), trimming whitespace from keys and values and discarding empty keys.
func cfgMap(cfg map[string]any, key string) map[string]string {
	raw, ok := cfg[key].(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		out[k] = s
	}
	return out
}
