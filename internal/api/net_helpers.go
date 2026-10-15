package api

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

func insecureTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

func nilContext() context.Context { return context.Background() }

type fsStat struct {
	Blocks uint64
	Bavail uint64
	Bsize  uint64
}

func statfs(path string) (fsStat, error) {
	var st syscallStatfs
	if err := statfsRaw(path, &st); err != nil {
		return fsStat{}, err
	}
	return fsStat{Blocks: uint64(st.Blocks), Bavail: uint64(st.Bavail), Bsize: uint64(st.Bsize)}, nil
}

// directResolve resolves host via a specific UDP DNS server (e.g. 1.1.1.1).
func directResolve(server, host string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", server+":53")
		},
	}
	return r.LookupHost(context.Background(), host)
}
