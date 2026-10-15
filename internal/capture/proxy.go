// Package capture is the recording MITM proxy (ScopeWeaver traffic-capture
// concept): on first start it generates a local CA; HTTPS traffic is
// intercepted with per-host forged certificates; every request/response pair
// is persisted as evidence. Tools pick it up via HTTP_PROXY/HTTPS_PROXY env
// injected into workflow runs when capture is enabled.
package capture

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k1nzr3c0n/internal/store"
)

const (
	maxBody = 64 * 1024 // captured body cap per direction
)

// Proxy is the recording proxy server.
type Proxy struct {
	Addr      string // listen address, default 127.0.0.1:8083
	st        *store.Store
	caCert    *x509.Certificate
	caKey     *rsa.PrivateKey
	mu        sync.Mutex
	certCache map[string]tls.Certificate
	enabled   bool
	runIDMu   sync.Mutex
	runStack  []string
}

// New creates (or loads) the CA and returns a proxy bound to the store.
func New(st *store.Store, baseDir string) (*Proxy, error) {
	p := &Proxy{
		Addr: envOr("K1NZR3C0N_PROXY_ADDR", "127.0.0.1:8083"),
		st:   st, certCache: map[string]tls.Certificate{},
	}
	caDir := filepath.Join(baseDir, "ca")
	if err := os.MkdirAll(caDir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(caDir, "ca-cert.pem")
	keyPath := filepath.Join(caDir, "ca-key.pem")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := genCA(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("generate CA: %w", err)
		}
		log.Printf("[capture] generated new CA at %s — import ca-cert.pem into the trust store of tools that need it", certPath)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	caTLS, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(caTLS.Certificate[0])
	p.caCert = leaf
	p.caKey = caTLS.PrivateKey.(*rsa.PrivateKey)
	return p, nil
}

// CACertPath returns the CA certificate path (for trust-store import).
func (p *Proxy) CACertPath(baseDir string) string {
	return filepath.Join(baseDir, "ca", "ca-cert.pem")
}

// Enabled reports whether capture is on.
func (p *Proxy) Enabled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.enabled
}

// SetEnabled flips capture; starting the listener when enabling.
func (p *Proxy) SetEnabled(on bool) error {
	p.mu.Lock()
	already := p.enabled
	p.enabled = on
	p.mu.Unlock()
	if on && !already {
		return p.start()
	}
	return nil
}

// serveTunnel reads HTTP/1.1 requests off one TLS connection until the peer
// closes or idles, dispatching each through the MITM handler.
func (p *Proxy) serveTunnel(conn *tls.Conn, host, runID string) {
	handler := &mitmHandler{p: p, tlsPeer: host, runID: runID}
	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		if req.URL.Host == "" {
			req.URL.Host = host
		}
		rec := &tunnelRecorder{hdr: make(http.Header), buf: &bytes.Buffer{}}
		handler.ServeHTTP(rec, req)
		resp := rec.build()
		_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if err := resp.Write(conn); err != nil {
			return
		}
		if req.Close {
			return
		}
	}
}

// tunnelRecorder is a minimal ResponseWriter capturing one response.
type tunnelRecorder struct {
	hdr    http.Header
	buf    *bytes.Buffer
	status int
}

func (t *tunnelRecorder) Header() http.Header         { return t.hdr }
func (t *tunnelRecorder) Write(b []byte) (int, error) { return t.buf.Write(b) }
func (t *tunnelRecorder) WriteHeader(code int)        { t.status = code }

func (t *tunnelRecorder) build() *http.Response {
	code := t.status
	if code == 0 {
		code = 200
	}
	return &http.Response{
		StatusCode: code,
		Status:     http.StatusText(code),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header:        t.hdr,
		Body:          io.NopCloser(bytes.NewReader(t.buf.Bytes())),
		ContentLength: int64(t.buf.Len()),
	}
}

// pushRun/popRun maintain a per-goroutine run binding. HTTP handler
// goroutines push on entry; nested pushes (CONNECT → tunneled request) keep
// the outermost binding authoritative via the explicit runID field.
func (p *Proxy) pushRun(id string) {
	p.runIDMu.Lock()
	p.runStack = append(p.runStack, id)
	p.runIDMu.Unlock()
}

func (p *Proxy) popRun() {
	p.runIDMu.Lock()
	if n := len(p.runStack); n > 0 {
		p.runStack = p.runStack[:n-1]
	}
	p.runIDMu.Unlock()
}

func (p *Proxy) currentRunID() *string {
	p.runIDMu.Lock()
	defer p.runIDMu.Unlock()
	n := len(p.runStack)
	if n == 0 || p.runStack[n-1] == "" {
		return nil
	}
	id := p.runStack[n-1]
	return &id
}

// runIDFromAuth decodes "Basic base64(runid:)" proxy auth into the run id.
func runIDFromAuth(header string) string {
	if header == "" {
		return ""
	}
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return ""
	}
	user, _, _ := strings.Cut(string(raw), ":")
	return user
}

func (p *Proxy) start() error {
	ln, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}
	go func() {
		srv := &http.Server{
			Handler:   &proxyHandler{p: p},
			ConnState: func(c net.Conn, state http.ConnState) {},
		}
		// wrap with TLS-detecting listener: CONNECT is plain; MITM conns
		// arrive as TLS after we hijack — handled inside proxyHandler.
		log.Printf("[capture] recording proxy listening on %s", p.Addr)
		_ = srv.Serve(ln)
	}()
	return nil
}

type proxyHandler struct{ p *Proxy }

func (h *proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	// plain HTTP proxy request; run id rides in Proxy-Authorization basic user
	rid := runIDFromAuth(r.Header.Get("Proxy-Authorization"))
	h.p.pushRun(rid)
	defer h.p.popRun()
	h.p.mitmRoundTrip(w, r, r.Host, false)
}

func (h *proxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	runID := runIDFromAuth(r.Header.Get("Proxy-Authorization"))
	// keep the binding visible for the tunneled requests too
	h.p.pushRun(runID)
	defer h.p.popRun()

	hij, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hij.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	cert, err := h.p.certFor(hostOnly(host))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if rawHost, _, err := net.SplitHostPort(host); err == nil && rawHost != "" {
		tlsCfg.ServerName = rawHost
	} else {
		tlsCfg.ServerName = host
	}
	tlsConn := tls.Server(clientConn, tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	// Serve HTTP/1.1 over the TLS tunnel with a hand-rolled loop. Using
	// http.Server+listener here either busy-spins (always-return Accept) or
	// returns early on second Accept (EOF) and closes the conn mid-request.
	h.p.serveTunnel(tlsConn, host, runID)
}

type mitmHandler struct {
	p       *Proxy
	tlsPeer string
	runID   string // captured from the CONNECT's proxy auth
}

func (m *mitmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		r.URL.Host = m.tlsPeer
		if !strings.Contains(r.URL.Host, ":") {
			r.URL.Scheme = "https"
			r.URL.Host = net.JoinHostPort(m.tlsPeer, "443")
		}
	}
	m.p.mitmRoundTrip(w, r, m.tlsPeer, true)
}

// mitmRoundTrip forwards the request upstream and records the exchange.
func (p *Proxy) mitmRoundTrip(w http.ResponseWriter, r *http.Request, peer string, isTLS bool) {
	if !p.Enabled() {
		// pass-through without recording
		p.forward(w, r, nil)
		return
	}
	reqDump := dumpRequest(r)

	outURL := *r.URL
	if outURL.Scheme == "" {
		if isTLS {
			outURL.Scheme = "https"
		} else {
			outURL.Scheme = "http"
		}
	}
	req2 := r.Clone(r.Context())
	req2.URL = &outURL
	req2.RequestURI = ""
	removeHopHeaders(req2.Header)

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: false,
	}
	resp, err := tr.RoundTrip(req2)
	if err != nil {
		http.Error(w, "capture proxy: "+err.Error(), http.StatusBadGateway)
		p.record(peer, r, reqDump, "", err)
		return
	}
	defer resp.Body.Close()
	respDump, body := dumpResponse(resp)

	// relay response from the SAME buffer the dump read (binary-safe,
	// no size truncation between dump and relay)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)

	p.record(peer, r, reqDump, respDump, nil)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, _ []byte) {
	outURL := *r.URL
	if outURL.Scheme == "" {
		outURL.Scheme = "http"
	}
	req2 := r.Clone(r.Context())
	req2.URL = &outURL
	req2.RequestURI = ""
	removeHopHeaders(req2.Header)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	resp, err := tr.RoundTrip(req2)
	if err != nil {
		http.Error(w, "proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *Proxy) record(peer string, r *http.Request, reqDump string, respDump string, err error) {
	method := r.Method
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	rec := &store.TrafficPair{
		RunID: p.currentRunID(), Host: peer, Method: method, Path: path,
		Request: capStr(reqDump), Response: capStr(respDump),
	}
	if respDump != "" {
		sc := parseStatus(respDump)
		rec.StatusCode = sc
	}
	if err != nil {
		rec.Response = "error: " + err.Error()
	}
	_ = p.st.InsertTraffic(rec)
}

// ── certificate forging ──────────────────────────────────────────────────────

func (p *Proxy) certFor(host string) (tls.Certificate, error) {
	p.mu.Lock()
	if c, ok := p.certCache[host]; ok {
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * 365 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	p.mu.Lock()
	if len(p.certCache) > 512 { // bounded memory: certs are cheap to re-forge
		p.certCache = map[string]tls.Certificate{}
	}
	p.certCache[host] = cert
	p.mu.Unlock()
	return cert, nil
}

func genCA(certPath, keyPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "k1nzr3c0n recording CA", Organization: []string{"k1nzr3c0n"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certOut := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyOut := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certPath, certOut, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyOut, 0o600)
}

// ── single-conn listener (serves HTTP over one hijacked TLS conn) ───────────

// singleConnListener serves exactly ONE connection, then reports EOF so
// http.Server stops (a naive always-return listener busy-spins on the closed
// conn forever).
type singleConnListener struct {
	c    net.Conn
	done bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, io.EOF
	}
	l.done = true
	return l.c, nil
}
func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.c.LocalAddr() }

// ── helpers ──────────────────────────────────────────────────────────────────

func hostOnly(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	return h
}

func removeHopHeaders(h http.Header) {
	for _, k := range []string{"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Connection", "Keep-Alive", "Te", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}

func capStr(s string) string {
	if len(s) > 2*maxBody {
		return s[:2*maxBody] + "\n[... truncated ...]"
	}
	return s
}

func parseStatus(dump string) int {
	// "HTTP/1.1 200 OK"
	if len(dump) > 12 && strings.HasPrefix(dump, "HTTP/") {
		var code int
		if _, err := fmt.Sscanf(dump[9:12], "%d", &code); err == nil {
			return code
		}
	}
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
