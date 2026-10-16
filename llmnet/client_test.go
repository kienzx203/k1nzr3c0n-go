package llmnet

import (
	"context"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalAddresses(t *testing.T) {
	for _, tc := range []struct {
		ip    string
		local bool
	}{{"127.0.0.1", true}, {"10.2.3.4", true}, {"172.16.0.1", true}, {"192.168.1.2", true}, {"::1", true}, {"fd12::1", true}, {"::ffff:127.0.0.1", true}, {"8.8.8.8", false}, {"169.254.169.254", false}, {"100.64.1.1", false}, {"fe80::1", false}, {"2001:4860:4860::8888", false}} {
		if got := IsLocalAddress(netip.MustParseAddr(tc.ip)); got != tc.local {
			t.Errorf("%s=%v", tc.ip, got)
		}
	}
}
func TestStrictPolicy(t *testing.T) {
	for _, proxy := range []string{"http://127.0.0.1:8080", "socks5://localhost:1080"} {
		if _, err := NewClient(proxy, true, nil); err == nil {
			t.Fatal("strict proxy accepted")
		}
	}
	if _, err := NewClient("", true, []string{"broken"}); err == nil {
		t.Fatal("bad CIDR accepted")
	}
	client, _ := NewClient("", true, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://203.0.113.4:81", nil)
	if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "not local or allowlisted") {
		t.Fatalf("public=%v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://203.0.113.4:81", http.StatusFound)
			return
		}
		fmt.Fprint(w, "local")
	}))
	defer srv.Close()
	if !IsLocalEndpoint(srv.URL) || IsLocalEndpoint("") || IsLocalEndpoint("https://203.0.113.4") {
		t.Fatal("endpoint classification")
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if _, err := client.Get(srv.URL + "/redirect"); err == nil || !strings.Contains(err.Error(), "local_llm_only") {
		t.Fatalf("redirect=%v", err)
	}
}
func TestAllowedCIDRReachesDialer(t *testing.T) {
	// A public documentation IP with a closed local test connection verifies policy
	// acceptance without sending packets: context is canceled before the actual dial.
	client, _ := NewClient("", true, []string{"203.0.113.0/24"})
	tr := client.Transport.(*http.Transport)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := tr.DialContext(ctx, "tcp", net.JoinHostPort("203.0.113.4", "81"))
	if err == nil || strings.Contains(err.Error(), "not local or allowlisted") {
		t.Fatalf("allowlist=%v", err)
	}
}
func TestDefaultAllowsConfiguredProxy(t *testing.T) {
	client, err := NewClient("http://localhost:8080", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr := client.Transport.(*http.Transport)
	req, _ := http.NewRequest("GET", "https://example.test", nil)
	u, err := tr.Proxy(req)
	if err != nil || u.Host != "localhost:8080" {
		t.Fatalf("proxy=%v %v", u, err)
	}
	client, _ = NewClient("", false, nil)
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy inherited")
	}
}

func TestLivePolicyDoesNotReuseUnrestrictedTransport(t *testing.T) {
	strict := false
	client, err := NewClientWithPolicy("http://127.0.0.1:9999", func() (bool, []string) { return strict, nil })
	if err != nil {
		t.Fatal(err)
	}
	transport := client.Transport.(*policyTransport)
	calls := 0
	transport.normal = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: http.Header{}}, nil
	})
	req, _ := http.NewRequest("GET", "http://203.0.113.1/", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	strict = true
	if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "proxies are not allowed") {
		t.Fatalf("live strict proxy error=%v", err)
	}
	if calls != 1 {
		t.Fatalf("unrestricted transport reused after strict toggle: %d", calls)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestDNSRebindingChecksTheSocketDestination(t *testing.T) {
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	var rebound atomic.Bool
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, peer, err := socket.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			reply := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, q := range query.Questions {
				if q.Type == dnsmessage.TypeA {
					address := [4]byte{127, 0, 0, 1}
					if rebound.Load() {
						address = [4]byte{203, 0, 113, 1}
					}
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}, Body: &dnsmessage.AResource{A: address}})
				}
			}
			data, err := reply.Pack()
			if err == nil {
				socket.WriteTo(data, peer)
			}
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", socket.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = previous }()
	if !IsLocalEndpoint("http://dns-rebind.test:11434") {
		t.Fatal("initial private DNS rejected")
	}
	rebound.Store(true)
	client, _ := NewClient("", true, nil)
	_, err = client.Get("http://dns-rebind.test:11434")
	if err == nil || !strings.Contains(err.Error(), "not local or allowlisted") {
		t.Fatalf("rebound DNS destination not rejected: %v", err)
	}
}
