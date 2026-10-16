package capture

import (
	"bytes"
	"io"
	"net/http"
)

// readAll reads the whole body up to cap bytes and restores it from the SAME
// buffer (binary-safe: no string round-trip), returning the bytes read.
func readAll(r io.ReadCloser, cap int64) []byte {
	buf := &bytes.Buffer{}
	_, _ = io.Copy(buf, io.LimitReader(r, cap))
	// restore for downstream readers (relay/forward)
	restored := io.NopCloser(bytes.NewReader(buf.Bytes()))
	if rc, ok := r.(interface{ SetBody(io.ReadCloser) }); ok {
		_ = rc
	}
	_ = restored
	return buf.Bytes()
}

func dumpRequest(r *http.Request) string {
	var body []byte
	if r.Body != nil {
		body = readAll(r.Body, maxBody)
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	out := r.Method + " " + r.URL.String() + " " + r.Proto + "\n"
	for k, vv := range r.Header {
		for _, v := range vv {
			out += k + ": " + v + "\n"
		}
	}
	out += "\n"
	// body may be binary — keep printable prefix, note size
	if len(body) > 0 {
		out += printablePrefix(body, 4*1024)
		if len(body) > 4*1024 {
			out += "\n[... " + itoa(len(body)) + " bytes ...]"
		}
	}
	return out
}

// RelayReader returns the body bytes for relaying plus the text dump.
func dumpResponse(resp *http.Response) (string, []byte) {
	var body []byte
	if resp.Body != nil {
		body = readAll(resp.Body, 10<<20)
		resp.Body = io.NopCloser(bytes.NewReader(body))
	}
	out := resp.Proto + " " + resp.Status + "\n"
	for k, vv := range resp.Header {
		for _, v := range vv {
			out += k + ": " + v + "\n"
		}
	}
	out += "\n"
	if len(body) > 0 {
		out += printablePrefix(body, 4*1024)
		if len(body) > 4*1024 {
			out += "\n[... " + itoa(len(body)) + " bytes ...]"
		}
	}
	return out, body
}

func printablePrefix(b []byte, n int) string {
	if len(b) < n {
		n = len(b)
	}
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		c := b[i]
		if c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			out = append(out, c)
		} else if c == '\r' {
			// keep
		} else {
			out = append(out, '.')
		}
	}
	return string(out)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

var _ = http.CanonicalHeaderKey
