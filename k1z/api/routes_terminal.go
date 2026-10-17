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

// PTY sessions keyed by session ID; survive disconnect, killed after 30min
// idle. A new socket for the same session displaces the old one (close 4000
// "session taken over" — Python parity).
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

func (p *ptySession) closeConns(reason string) {
	for c := range p.conns {
		go c.Close(4000, reason)
	}
	p.conns = map[*websocket.Conn]struct{}{}
}

func (p *ptySession) write(b []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tty.Write(b)
	p.last = time.Now()
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
	set("SHELL", "/bin/bash")
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
	cmd := exec.Command("/bin/bash", "-l")
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
	go func() { // reap on exit
		cmd.Wait()
		ptyMu.Lock()
		delete(ptySessions, sessionID)
		ptyMu.Unlock()
	}()
	return s, nil
}

// handleTerminalWS is the browser terminal: binary frames = raw PTY bytes,
// text frames = {"type":"resize","rows":N,"cols":N}.
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

	// takeover: displace any previous socket for this session (close 4000)
	ptyMu.Lock()
	if sess.conns == nil {
		sess.conns = map[*websocket.Conn]struct{}{}
	}
	for prev := range sess.conns {
		go prev.Close(4000, "session taken over")
	}
	sess.conns = map[*websocket.Conn]struct{}{conn: {}}
	ptyMu.Unlock()
	defer func() {
		ptyMu.Lock()
		delete(sess.conns, conn)
		ptyMu.Unlock()
	}()

	// PTY → client
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 8192)
		for {
			n, err := sess.tty.Read(buf)
			if n > 0 {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				if werr := conn.Write(ctx, websocket.MessageBinary, buf[:n]); werr != nil {
					cancel()
					return
				}
				cancel()
				sess.last = time.Now()
			}
			if err != nil {
				return
			}
		}
	}()

	// client → PTY
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
	select {
	case <-readerDone:
	default:
		sess.tty.Close() // unblock reader
		<-readerDone
	}
	log.Printf("[terminal] session %s closed", sessionID)
}
