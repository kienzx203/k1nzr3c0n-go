package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// weComMarkdownLimit is the hard limit on a WeCom group bot's markdown content
// (bytes, not characters). It is the tightest limit of all six channels, and the
// main reason TruncateBytes exists.
const weComMarkdownLimit = 4096

// weComChannel implements the WeCom group bot.
//
// Platform characteristics:
//   - Authenticated solely by the key on the URL; signing is not supported — so
//     the webhook address itself is the entire set of credentials.
//   - markdown content is capped at 4096 **bytes**; an over-length message is
//     rejected entirely (not truncated). Chinese characters are 3 bytes each,
//     which means the body only has room for a thousand-odd characters, so
//     client-side truncation is mandatory.
//   - Rate-limited to 20 messages/minute, also handled by client-side rate
//     limiting.
type weComChannel struct{}

func (weComChannel) Kind() string { return KindWeCom }

func (weComChannel) DefaultRatePerMin() int { return 20 }

// WeCom has only one credential, the Webhook (the key on the URL), and it does
// not support signing — the whole address is the entire set of credentials, so
// there is no other field to mask.
func (weComChannel) SecretKeys() []string { return []string{"webhook"} }

// WeCom has only one field, the Webhook; it is both the destination and the
// credential, so there is no such thing as a "credential left over after
// changing the address".
func (weComChannel) DestinationKeys() []string { return []string{"webhook"} }

func (weComChannel) Validate(cfg map[string]any) error {
	hook := cfgString(cfg, "webhook")
	if hook == "" {
		return errors.New("missing Webhook address")
	}
	if err := validateHTTPURL(hook); err != nil {
		return fmt.Errorf("invalid Webhook address: %w", err)
	}
	return nil
}

func (c weComChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	// A digest batch can be very long (50 items × one line each + prefix), so
	// 4096 bytes is easily exceeded. Truncation is done here rather than relying
	// on a platform error: being rejected means the whole batch is lost, whereas
	// truncation at least delivers the first several items.
	content, kept := markdownBody(m, weComMarkdownLimit)
	payload := map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]any{"content": content},
	}
	raw, err := doJSON(ctx, "POST", cfgString(cfg, "webhook"), nil, payload)
	if err != nil {
		return 0, err
	}
	var res struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return 0, fmt.Errorf("failed to parse WeCom response: %w (%s)", err, snippet(raw))
	}
	if res.ErrCode != 0 {
		// 45009 means the API call exceeded the limit — the platform's rate-limit
		// window rolls, so retrying after a backoff is effective, which is why
		// it's explicitly classified as retryable. Reaching here means the
		// client-side rate_per_min is configured too aggressively; the retry is
		// just a fallback, and the real fix is to lower that channel's rate limit.
		if res.ErrCode == 45009 {
			return 0, fmt.Errorf("WeCom rate limited %d: %s", res.ErrCode, res.ErrMsg)
		}
		// 93000 means the webhook key is invalid — a permanent failure that a
		// retry won't heal.
		return 0, Permanent(fmt.Errorf("WeCom returned error %d: %s", res.ErrCode, res.ErrMsg))
	}
	return kept, nil
}
