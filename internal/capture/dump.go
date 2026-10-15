package capture

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

func dumpRequest(r *http.Request) string {
	body := []byte{}
	if r.Body != nil {
		b, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
		if err == nil {
			body = b
		}
		r.Body = io.NopCloser(strings.NewReader(string(body))) // restore for forward
	}
	out := fmt.Sprintf("%s %s %s\n", r.Method, r.URL.String(), r.Proto)
	for k, vv := range r.Header {
		for _, v := range vv {
			out += k + ": " + v + "\n"
		}
	}
	out += "\n" + string(body)
	return out
}

func dumpResponse(resp *http.Response) string {
	body := []byte{}
	if resp.Body != nil {
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err == nil {
			body = b
		}
		resp.Body = io.NopCloser(strings.NewReader(string(body))) // restore for relay
	}
	out := fmt.Sprintf("%s %s\n", resp.Proto, resp.Status)
	for k, vv := range resp.Header {
		for _, v := range vv {
			out += k + ": " + v + "\n"
		}
	}
	out += "\n" + string(body)
	return out
}

var _ = httputil.DumpRequest
var _ = bufio.NewReader
