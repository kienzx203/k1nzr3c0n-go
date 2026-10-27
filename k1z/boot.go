// Package k1z boots k1nzr3c0n's workflow-runner backend (its own SQLite store +
// runner + scheduler) so it can be mounted inside the ScopeWeaver binary. Its
// routes live under /api/v1/* and /ws/*; ScopeWeaver owns everything else.
package k1z

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/Autumn-27/artex/k1z/agent"
	"github.com/Autumn-27/artex/k1z/api"
	"github.com/Autumn-27/artex/k1z/bus"
	"github.com/Autumn-27/artex/k1z/capture"
	"github.com/Autumn-27/artex/k1z/config"
	"github.com/Autumn-27/artex/k1z/enrich"
	"github.com/Autumn-27/artex/k1z/explore"
	"github.com/Autumn-27/artex/k1z/notify"
	"github.com/Autumn-27/artex/k1z/runner"
	"github.com/Autumn-27/artex/k1z/schedule"
	"github.com/Autumn-27/artex/k1z/store"
)

// BuildHandler initializes the k1nzr3c0n backend and returns an http.Handler for
// its /api/v1/* + /ws/* routes plus a shutdown func. On error the ScopeWeaver
// server still runs; the workflow-runner features are simply unavailable.
func BuildHandler(ctx context.Context) (http.Handler, func(), error) {
	st, err := store.OpenAuto(config.DBPath())
	if err != nil {
		return nil, func() {}, fmt.Errorf("k1z open db: %w", err)
	}
	if store.PostgresDSN() != "" {
		fmt.Println("[k1z] store backend: PostgreSQL (schema k1z, via K1Z_PG_DSN)")
	} else {
		fmt.Printf("[k1z] store backend: SQLite (%s)\n", config.DBPath())
	}
	b := bus.New()
	r := runner.New(st, b)
	r.Start(config.WorkerConcurrency())

	cap, capErr := capture.New(st, config.BaseDir())
	if capErr != nil {
		fmt.Printf("[k1z] capture proxy unavailable: %v\n", capErr)
	}
	r.ProxyEnv = func(runID string) map[string]string {
		if cap == nil || !cap.Enabled() {
			return nil
		}
		p := "http://" + runID + "@" + cap.Addr
		return map[string]string{
			"HTTP_PROXY": p, "HTTPS_PROXY": p, "http_proxy": p, "https_proxy": p,
			"NO_PROXY": "localhost,127.0.0.1",
		}
	}

	agent.SeedAgentRules(st)
	st.SeedAgentConfigs()
	notify.DBWebhookURL = func() string { return st.GetNotifySettings().WebhookURL }

	cctx, cancel := context.WithCancel(ctx)
	schedule.Start(cctx, st, r)
	enrich.Start(cctx, st)

	srv := api.New(st, b, r)
	srv.Cap = cap
	proxyAddr := ""
	if cap != nil {
		proxyAddr = cap.Addr
	}
	srv.Explore = explore.NewManager(st, b, proxyAddr)

	shutdown := func() { cancel(); _ = st.Close() }
	return srv.Handler(), shutdown, nil
}

// Mount returns a handler that routes k1nzr3c0n's paths to k1zHandler and
// everything else to the ScopeWeaver handler.
func Mount(sw http.Handler, k1zHandler http.Handler) http.Handler {
	if k1zHandler == nil {
		return sw
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/v1/") || strings.HasPrefix(p, "/ws/") {
			k1zHandler.ServeHTTP(w, r)
			return
		}
		sw.ServeHTTP(w, r)
	})
}
