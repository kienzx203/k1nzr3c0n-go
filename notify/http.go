package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// allowLocalTargets decides whether messages may be delivered to loopback /
// link-local addresses.
//
// Denied by default. These address ranges are not where IM bots or public mail
// servers live, and what they can reach is sensitive: the admin port of another
// service on the same host, and the cloud metadata endpoint
// (169.254.169.254, which can leak instance credentials). The delivery address is
// set by the admin, but an admin session borrowed via XSS/CSRF, or a second person
// sharing the same JWT, can read response content back by changing the config
// — doJSON writes the first 200 bytes of a 4xx/5xx response body into last_error,
// and the delivery-history endpoint echoes it back, which makes it a semi-blind
// read primitive.
//
// But a "local SMTP relay" (postfix on 127.0.0.1:25) is a common self-hosted mail
// setup, and blocking it wholesale would get people stuck. So we leave an explicit
// escape hatch rather than hardcoding an allow:
// set ARTEX_NOTIFY_ALLOW_LOCAL=1 to permit it.
//
// It is exported as AllowLocalTargetsEnv so tests can turn it on explicitly — the
// test cases in this package and the server package make heavy use of httptest fake
// receivers on 127.0.0.1, which would all be blocked by the guard otherwise.
const AllowLocalTargetsEnv = "ARTEX_NOTIFY_ALLOW_LOCAL"

func allowLocalTargets() bool {
	v := strings.TrimSpace(os.Getenv(AllowLocalTargetsEnv))
	return v == "1" || strings.EqualFold(v, "true")
}

// isBlockedDialIP reports whether the target IP falls in an address range that is
// "not allowed for delivery by default".
//
// It rejects only loopback, link-local (including cloud metadata 169.254.169.254),
// unspecified and multicast.
// It does **not** reject RFC1918 private networks: an internally self-hosted
// Mattermost / SMTP relay is a very common legitimate use, and blocking those too
// would make the feature outright unusable in real environments. This trade-off is
// deliberate — the protection must block genuinely sensitive targets while not
// breaking normal deployments along with them.
func isBlockedDialIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// IPv4-mapped IPv6 (::ffff:127.0.0.1) must be converted back to IPv4 before checking, otherwise it bypasses the check.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast()
}

// blockInternalDial is the Control hook of the http.Transport dialer, checking the
// target address **at connection establishment time**.
//
// Why it is placed at the dial stage rather than only validating when the config is
// saved: this is the final point of enforcement. It covers both ways of bypassing
// config validation — DNS rebinding (resolving to a public IP at validation time
// and to an internal address at actual connection time) and redirects (although we
// already reject cross-host hops, a same-host hop can still point the path
// elsewhere).
func blockInternalDial(_, address string, _ syscall.RawConn) error {
	if allowLocalTargets() {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("cannot resolve target address %q", host)
	}
	if isBlockedDialIP(ip) {
		return fmt.Errorf("refusing to deliver to local/link-local address %s (if you really need to deliver to a local service, set %s=1)", ip, AllowLocalTargetsEnv)
	}
	return nil
}

// notifyTransport adds only a dial guard on top of the default Transport.
// It uses Clone to preserve all the default tuning (connection pool, HTTP/2,
// timeouts, proxy, etc.), avoiding changing other behavior just to add one check.
var notifyTransport = func() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{}
	}
	clone := t.Clone()
	clone.DialContext = (&net.Dialer{Timeout: 10 * time.Second, Control: blockInternalDial}).DialContext
	return clone
}()

// httpClient is the client shared by all channel deliveries.
//
// It deliberately does **not** reuse the project's global egress proxy (GlobalProxy
// on the server side): that proxy is for pentest target traffic and is often an
// unstable tunnel, whereas notification availability should not be held hostage by
// jitter on the target network. IM pushes can connect directly. The timeout is set
// to 15 seconds — a peer slower than that is effectively already in a failed state.
//
// It rejects cross-host redirects: this feature's delivery addresses are all of the
// "one fixed endpoint" form and normally will not redirect to another host; and
// these vendors' credentials (DingTalk's access_token, WeCom's key, Telegram's bot
// token) are **right in the URL**, so following a cross-host hop hands the
// credentials to the redirect target. Same-host hops (such as appending a trailing
// slash) are still allowed.
var httpClient = &http.Client{
	Timeout:   15 * time.Second,
	Transport: notifyTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if len(via) > 0 && req.URL.Host != via[0].URL.Host {
			return fmt.Errorf("refusing cross-host redirect (%s → %s)", via[0].URL.Host, req.URL.Host)
		}
		return nil
	},
}

// respBodyLimit limits the size of the response body we read. A misbehaving peer
// may spit back huge content, while we only need the error code and a short error
// description to show in the delivery history.
const respBodyLimit = 8 << 10

// doJSON sends one request and returns the response body (length-limited).
//
// When payload is nil it sends an empty body (for GET or platforms that don't
// require a body). The key/values in headers are attached as-is, used for the
// generic Webhook's custom headers.
//
// Error classification is this function's core responsibility: network-layer
// failures and 5xx/408/429 are grouped as "retryable", other 4xx as "permanent
// failure" — retrying a 403 just prints the same error to the log three times.
func doJSON(ctx context.Context, method, url string, headers map[string]string, payload any) ([]byte, error) {
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			// A serialization failure is a local bug (wrong config field type); retrying won't help.
			return nil, Permanent(fmt.Errorf("failed to build request body: %w", err))
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		// Invalid URL — most likely the user entered the address wrong, a permanent failure.
		// Here too we must not pass err through: url.Parse's error text contains the full address.
		return nil, Permanent(fmt.Errorf("invalid request address: %s", redactRequestTarget(url)))
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// Connection refused, DNS failure, timeout — mostly transient faults, left to backoff retry.
		//
		// The error text must be redacted before being passed outward. Reason: http.Client.Do
		// returns a *url.Error whose Error() is `Op "fullURL": underlying error`, and these
		// vendors' credentials are **right in the URL**
		// (DingTalk access_token, WeCom key, Feishu hook id, Telegram /bot<token>/).
		// Without redaction, the credentials would flow along this error string to four places:
		// notification_deliveries' last_error (stored in plaintext), the delivery-history
		// endpoint's response (**bypassing the channel config's masking**), the server log, and
		// the 502 text the test-send endpoint returns to the frontend.
		return nil, fmt.Errorf("request failed: %s", redactTransportError(err))
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(resp.Body, respBodyLimit))
	if readErr != nil {
		return nil, fmt.Errorf("failed to read response: %w", readErr)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return raw, nil
	}
	// 429 (rate limit) and 408 (timeout) are worth retrying; other 4xx are config or permission issues where retrying is pointless.
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		return nil, fmt.Errorf("peer rate-limited or timed out (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("peer service error (HTTP %d): %s", resp.StatusCode, snippet(raw))
	}
	return nil, Permanent(fmt.Errorf("peer rejected request (HTTP %d): %s", resp.StatusCode, snippet(raw)))
}

// snippet squeezes the response body into a short single line, for error messages.
// The response may contain newlines and lots of whitespace; stuffing it straight
// into last_error would break the layout of the delivery-history page.
func snippet(raw []byte) string {
	return OneLine(string(raw), 200)
}

// redactRequestTarget squeezes the delivery address down to "scheme://host/…", for
// error messages.
//
// This is the only address-redaction rule in the package, deliberately made
// **blunt enough**: everything except scheme and host is discarded. The reason is
// that there is no "general and safe" way to tell which part of a URL is the
// credential:
//
//	DingTalk credential in query                /robot/send?access_token=xxx
//	WeCom    credential in query                /cgi-bin/webhook/send?key=xxx
//	Feishu   credential in **last path segment**   /open-apis/bot/v2/hook/<hook_id>
//	Telegram credential in **middle path segment** /bot<token>/sendMessage
//
// Wanting to "keep only the useful part" would require patching per channel, and
// missing any one vendor is a credential leak. Keeping the host is already enough
// for troubleshooting (DNS not resolving, connection failing, or a bad certificate
// can all be pinpointed), and exactly which bot it is can be recognized from the
// masked-suffix hint in the channel config.
//
// On parse failure it returns a fixed placeholder — it never echoes the original
// string back out.
func redactRequestTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(address not parseable)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// redactTransportError strips the address out of a transport-layer error, keeping
// only the underlying cause.
//
// *url.Error's structure is {Op, URL, Err}, and Error() prints the URL along with
// it. Here we take the Err field explicitly, bypassing its Error() — more reliable
// than doing string replacement after the fact, because replacement would have to
// correctly handle all the variants after URL encoding/escaping and easily misses
// some.
func redactTransportError(err error) string {
	var uerr *url.Error
	if errors.As(err, &uerr) {
		host := ""
		if u, parseErr := url.Parse(uerr.URL); parseErr == nil {
			host = u.Host
		}
		if uerr.Err != nil {
			return fmt.Sprintf("%s %s: %s", uerr.Op, host, uerr.Err)
		}
		return fmt.Sprintf("%s %s: unknown error", uerr.Op, host)
	}
	// Non-*url.Error cases (such as errors returned by the redirect policy) may also carry addresses, so run them all through redaction.
	return redactURLsInText(err.Error())
}

// redactURLsInText replaces http(s) addresses appearing in a piece of text with
// their redacted form.
//
// Used as a fallback for errors where structured fields aren't available (redirect
// policy errors, custom errors from third-party libraries). It recognizes only
// http/https prefixes and splits on whitespace and quotes — addresses won't contain
// either kind of character.
func redactURLsInText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		if strings.HasPrefix(rest, "http://") || strings.HasPrefix(rest, "https://") {
			end := len(rest)
			if j := strings.IndexAny(rest, " \t\n\"'"); j >= 0 {
				end = j
			}
			b.WriteString(redactRequestTarget(rest[:end]))
			i += end
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
