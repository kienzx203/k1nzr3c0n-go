package api

import (
	crand "crypto/rand"
	"encoding/hex"

	"k1nzr3c0n/internal/config"
	"k1nzr3c0n/internal/parsers"
	"k1nzr3c0n/internal/store"
)

func token() string { return config.APIToken() }

func randRead(b []byte) (int, error) { return crand.Read(b) }

func hexB(b []byte) string { return hex.EncodeToString(b) }

// reparseRunner re-runs the findings parsers for one run (used by reparse + ws).
func reparseRunner(s *Server, run *store.Run) error {
	return parsers.ParseWorkspace(s.St, run, s.Bus)
}
