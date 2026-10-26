package server

import (
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/locale"
	"testing"
)

func TestSeededAgentMetadataLocalePreservesEdits(t *testing.T) {
	// Stock reporter/retester are English-only now: localization forces English for
	// any stock/legacy value regardless of the request language.
	for _, tc := range []struct{ key, name, want string }{
		{"reporter", "Report writer", "Report writer"},
		{db.FindingRetestAgentKey, "Finding retest", "Finding retest"},
	} {
		original := &db.Agent{Key: tc.key, Name: tc.name, Description: "Custom description 원문"}
		result := agentDTO(original, locale.Ko)
		if result.Name != tc.want || result.Description != original.Description || original.Name != tc.name {
			t.Fatalf("stock metadata localization changed custom/stored content: %+v", result)
		}
		original.Name = "Custom name 원문"
		if result := agentDTO(original, locale.Ko); result.Name != original.Name {
			t.Fatal("custom name translated")
		}
	}
}

func TestSeededMetadataAllLanguagesReverseAndCustom(t *testing.T) {
	for _, lang := range locale.Languages() {
		a := &db.Agent{Key: "reporter", Name: locale.Text(lang, "Report writer"), Description: locale.Text(lang, "Writes detailed vulnerability reports: triggered by findings, reads evidence and execution traces, then saves a Markdown report.")}
		localizeSeededAgentMetadata(a, locale.En)
		if a.Name != "Report writer" || a.Description != "Writes detailed vulnerability reports: triggered by findings, reads evidence and execution traces, then saves a Markdown report." {
			t.Fatal("stock metadata reverse failed")
		}
		a.Name = "user custom"
		a.Description = "user custom"
		localizeSeededAgentMetadata(a, locale.ZhHans)
		if a.Name != "user custom" || a.Description != "user custom" {
			t.Fatal("edited metadata changed")
		}
	}
}
