package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/coder/websocket"
	"github.com/creack/pty"
)

// PTY sessions keyed by session ID. A session OWNS a long-lived shell + one
// reader goroutine that broadcasts PTY output to the currently-attached sockets.
// Sessions survive socket disconnect (switching browser tabs) and are reaped
// after 30min idle — closing a socket never kills the shell.
var (
	ptyMu       sync.Mutex
	ptySessions = map[string]*ptySession{}
)

type ptySession struct {
	tty   *os.File
	mu    sync.Mutex
	last  time.Time
	conns map[*websocket.Conn]struct{}
}

func (p *ptySession) write(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tty.Write(b)
	p.last = time.Now()
}

// broadcast fans PTY output out to every attached socket; a socket that errors
// is dropped (its own handler cleans up), the shell keeps running.
func (p *ptySession) broadcast(b []byte) {
	p.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.last = time.Now()
	p.mu.Unlock()
	for _, c := range conns {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := c.Write(ctx, websocket.MessageBinary, b)
		cancel()
		if err != nil {
			p.mu.Lock()
			delete(p.conns, c)
			p.mu.Unlock()
			go c.Close(websocket.StatusNormalClosure, "")
		}
	}
}

func (p *ptySession) addConn(c *websocket.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conns == nil {
		p.conns = map[*websocket.Conn]struct{}{}
	}
	p.conns[c] = struct{}{}
}

func (p *ptySession) dropConn(c *websocket.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conns, c)
}

type winsize struct {
	Rows, Cols, X, Y uint16
}

func (p *ptySession) resize(rows, cols uint16) {
	syscall.Syscall(syscall.SYS_IOCTL, p.tty.Fd(), uintptr(syscall.TIOCSWINSZ),
		uintptr(unsafe.Pointer(&winsize{Rows: rows, Cols: cols})))
}

func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			cutoff := time.Now().Add(-30 * time.Minute)
			ptyMu.Lock()
			for id, s := range ptySessions {
				if s.last.Before(cutoff) {
					s.tty.Close()
					delete(ptySessions, id)
				}
			}
			ptyMu.Unlock()
		}
	}()
}

// terminalHome returns a usable HOME for the shell. A server started by systemd
// often has no HOME in its environment, which breaks `cd`, shell startup files,
// and tools (e.g. opencode) that store their config under $HOME.
func terminalHome() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return "/root"
}

// loginShell returns the user's real login shell so the browser terminal behaves
// like their native terminal — in particular it sources the right rc file
// (~/.zshrc, ~/.bashrc, …), which is where tools like opencode add themselves to
// PATH. A hardcoded /bin/bash would never see a PATH export made only in .zshrc.
func loginShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		if _, err := os.Stat(sh); err == nil {
			return sh
		}
	}
	if u, err := user.Current(); err == nil {
		if data, err := os.ReadFile("/etc/passwd"); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				f := strings.Split(line, ":")
				if len(f) >= 7 && f[0] == u.Username && f[6] != "" {
					if _, err := os.Stat(f[6]); err == nil {
						return f[6]
					}
				}
			}
		}
	}
	return "/bin/bash"
}

// terminalEnv builds the PTY environment, guaranteeing HOME/USER/SHELL/PATH/LANG
// so the login shell and any spawned tools behave like a normal interactive
// session. Existing values from the server environment are never overridden.
func terminalEnv() []string {
	env := os.Environ()
	has := func(key string) bool {
		pref := key + "="
		for _, e := range env {
			if strings.HasPrefix(e, pref) {
				return true
			}
		}
		return false
	}
	set := func(key, val string) {
		if val != "" && !has(key) {
			env = append(env, key+"="+val)
		}
	}
	uname := ""
	if u, err := user.Current(); err == nil {
		uname = u.Username
	}
	set("HOME", terminalHome())
	set("USER", uname)
	set("LOGNAME", uname)
	set("SHELL", loginShell())
	set("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	set("LANG", "C.UTF-8")
	env = append(env, "TERM=xterm-256color", "COLORTERM=truecolor")
	return env
}

func getPTY(sessionID string) (*ptySession, error) {
	ptyMu.Lock()
	defer ptyMu.Unlock()
	if s, ok := ptySessions[sessionID]; ok {
		return s, nil
	}
	cmd := exec.Command(loginShell(), "-l")
	cmd.Env = terminalEnv()
	if home := terminalHome(); home != "" {
		cmd.Dir = home
	}
	tty, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: 24, Cols: 200})
	if err != nil {
		return nil, err
	}
	s := &ptySession{tty: tty, last: time.Now(), conns: map[*websocket.Conn]struct{}{}}
	ptySessions[sessionID] = s

	// One reader per session: PTY output -> broadcast to attached sockets. Runs
	// until the shell exits (tty read error); it does NOT stop on disconnect.
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := tty.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				s.broadcast(chunk)
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // reap on shell exit
		cmd.Wait()
		ptyMu.Lock()
		delete(ptySessions, sessionID)
		ptyMu.Unlock()
		tty.Close()
	}()
	return s, nil
}

// handleTerminalWS is the browser terminal: binary frames = raw PTY bytes,
// text frames = {"type":"resize","rows":N,"cols":N}. The socket only carries
// input to the PTY; output arrives via the session's broadcast reader. Closing
// the socket detaches this viewer but leaves the shell running.
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	sessionID := r.PathValue("session_id")
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	sess, err := getPTY(sessionID)
	if err != nil {
		return
	}

	// takeover: displace any previous socket for this session (close 4001 so the
	// old tab stops; parity with the "session taken over" behaviour).
	sess.mu.Lock()
	for prev := range sess.conns {
		go prev.Close(4001, "session taken over")
	}
	sess.conns = map[*websocket.Conn]struct{}{conn: {}}
	sess.last = time.Now()
	sess.mu.Unlock()
	defer sess.dropConn(conn)

	// client → PTY (output is delivered by the session reader via broadcast)
	for {
		mt, data, err := conn.Read(r.Context())
		if err != nil {
			break
		}
		switch mt {
		case websocket.MessageBinary:
			sess.write(data)
		case websocket.MessageText:
			var msg struct {
				Type string `json:"type"`
				Rows int    `json:"rows"`
				Cols int    `json:"cols"`
			}
			if json.Unmarshal(data, &msg) == nil && msg.Type == "resize" {
				rows, cols := msg.Rows, msg.Cols
				if rows < 1 {
					rows = 24
				}
				if cols < 1 {
					cols = 80
				}
				sess.resize(uint16(rows), uint16(cols))
			}
		}
	}
	log.Printf("[terminal] viewer detached from session %s", sessionID)
}
