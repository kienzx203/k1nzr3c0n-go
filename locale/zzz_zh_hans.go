package locale

import (
	_ "embed"
	"encoding/json"
)

//go:embed zh-Hans.json
var zhHansJSON []byte

// The Chinese catalog is registered after the base EN/KO registrations. Adding
// a translated value never replaces the authoritative English or Korean text.
func init() {
	var entries map[string]string
	if err := json.Unmarshal(zhHansJSON, &entries); err != nil {
		panic(err)
	}
	for key, text := range entries {
		RegisterAll(map[string]map[Lang]string{key: {ZhHans: text}})
	}
}
