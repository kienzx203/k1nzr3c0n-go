package api

import (
	crand "crypto/rand"
	"encoding/hex"

	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/parsers"
	"github.com/Autumn-27/artex/k1z/store"
)

func token() string { return config.APIToken() }

func randRead(b []byte) (int, error) { return crand.Read(b) }

func hexB(b []byte) string { return hex.EncodeToString(b) }

// reparseRunner re-runs the findings parsers for one run (used by reparse + ws).
func reparseRunner(s *Server, run *store.Run) error {
	return parsers.ParseWorkspace(s.St, run, s.Bus, true)
}
