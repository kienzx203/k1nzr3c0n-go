package api

import (
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/Autumn-27/artex/k1z/config"
	maxminddb "github.com/oschwald/maxminddb-golang"
)

// geoDBPath returns the first GeoLite2-City.mmdb found, or "".
func geoDBPath() string {
	if p := strings.TrimSpace(os.Getenv("K1NZR3C0N_GEODB")); p != "" {
		if fileExists(p) {
			return p
		}
	}
	for _, p := range []string{
		filepath.Join(config.BaseDir(), "GeoLite2-City.mmdb"),
		"/opt/k1nzr3c0n/GeoLite2-City.mmdb",
		"/usr/share/GeoIP/GeoLite2-City.mmdb",
		"/var/lib/GeoIP/GeoLite2-City.mmdb",
	} {
		if fileExists(p) {
			return p
		}
	}
	return ""
}

type geoPoint struct {
	ID   string  `json:"id"`
	Lat  float64 `json:"lat"`
	Lon  float64 `json:"lon"`
	CC   string  `json:"cc"`
	City string  `json:"city"`
}

// handleGraph2Geo geolocates the graph's IP nodes from a local MaxMind
// GeoLite2-City database. Entirely offline — no target IP leaves the host.
func (s *Server) handleGraph2Geo(w http.ResponseWriter, r *http.Request) {
	g := s.graphFor(w, r)
	if g == nil {
		return
	}
	path := geoDBPath()
	if path == "" {
		writeJSON(w, 200, map[string]any{"available": false,
			"hint": "drop GeoLite2-City.mmdb into the base dir, /opt/k1nzr3c0n/, or set K1NZR3C0N_GEODB"})
		return
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		writeJSON(w, 200, map[string]any{"available": false, "hint": "cannot open geo db: " + err.Error()})
		return
	}
	defer db.Close()

	var rec struct {
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Location struct {
			Lat float64 `maxminddb:"latitude"`
			Lon float64 `maxminddb:"longitude"`
		} `maxminddb:"location"`
	}

	pts := []geoPoint{}
	total := 0
	for id, n := range g.Nodes {
		if !strings.HasPrefix(n.Group, "ip") {
			continue
		}
		ip := net.ParseIP(n.Label)
		if ip == nil {
			continue
		}
		total++
		rec.Country.ISO = ""
		rec.City.Names = nil
		rec.Location.Lat, rec.Location.Lon = 0, 0
		if err := db.Lookup(ip, &rec); err != nil {
			continue
		}
		if rec.Location.Lat == 0 && rec.Location.Lon == 0 && rec.Country.ISO == "" {
			continue
		}
		pts = append(pts, geoPoint{ID: id, Lat: rec.Location.Lat, Lon: rec.Location.Lon,
			CC: rec.Country.ISO, City: rec.City.Names["en"]})
	}
	writeJSON(w, 200, map[string]any{"available": true, "points": pts,
		"meta": map[string]any{"located": len(pts), "ips": total}})
}
