package server

import (
	"encoding/json"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"testing"
)

func TestStoredToolAllLanguagesAndCustomFields(t *testing.T) {
	s := &Server{}
	variants := s.knownToolLanguages()
	for _, key := range []string{"node_detail", "get_finding_traffic"} {
		tools := variants[key]
		if tools[locale.En] == nil {
			t.Fatalf("missing stock tool %s", key)
		}
		for _, lang := range locale.Languages() {
			source := tools[lang]
			raw, _ := json.Marshal(source.InputSchema())
			row := &db.Tool{Key: key, System: true, Description: source.Description(), Schema: raw}
			reversed := translatedStoredTool(row, variants, locale.En)
			expected, _ := json.Marshal(tools[locale.En].InputSchema())
			if reversed.Description != tools[locale.En].Description() || string(reversed.Schema) != string(expected) {
				t.Fatalf("%s %s stock reverse failed", key, lang)
			}
			row.System = false
			custom := translatedStoredTool(row, variants, locale.En)
			if custom.Description != row.Description || string(custom.Schema) != string(row.Schema) {
				t.Fatal("custom tool changed")
			}
			row.System = true
			row.Description = "用户 custom"
			custom = translatedStoredTool(row, variants, locale.ZhHans)
			if custom.Description != row.Description || row.Description != "用户 custom" {
				t.Fatal("edited description mutated")
			}
		}
	}
}
