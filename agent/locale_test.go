package agent

import (
	"encoding/json"
	"github.com/Autumn-27/artex/locale"
	actool "github.com/Autumn-27/norma/tool"
	"strings"
	"testing"
)

func TestBuiltinPromptLanguageAndInterpolation(t *testing.T) {
	old := PromptOverride
	PromptOverride = nil
	defer func() { PromptOverride = old }()
	en := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: "user goal / 원문"}, locale.En)
	ko := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: "user goal / 원문"}, locale.Ko)
	if !strings.Contains(en, "You are the planner") || !strings.Contains(ko, "당신은") {
		t.Fatal("prompt language selection failed")
	}
	for _, text := range []string{en, ko} {
		if !strings.Contains(text, "user goal / 원문") || strings.Contains(text, "{{.Goal}}") {
			t.Fatal("goal altered or not interpolated")
		}
	}
}

func TestEditedPromptIsNotTranslated(t *testing.T) {
	old := PromptOverride
	defer func() { PromptOverride = old }()
	const custom = "user's own template {{.Goal}}"
	PromptOverride = func(string) (string, bool) { return custom, true }
	got := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: "original"}, locale.Ko)
	if got != "user's own template original" {
		t.Fatalf("edited prompt changed: %q", got)
	}
}

func TestBuiltinPromptTranslationCoverage(t *testing.T) {
	for _, p := range []string{goalsDefaultTmpl, goalsScopeTail, plannerDefaultTmpl, workerDefaultTmpl, mainAgentDefaultTmpl, autoDefaultTmpl, pentestDefaultTmpl, DefaultAssistantPrompt, ReporterDefaultPrompt, RetesterDefaultPrompt} {
		ko, ok := locale.Lookup(locale.Ko, p)
		if !ok || ko == p || strings.TrimSpace(ko) == "" {
			t.Fatalf("missing Korean prompt: %.60s", p)
		}
		for _, contract := range []string{"{{.Goal}}", "set_constraints", "add_task_scope", "report_finding", "update_finding_report", "record_finding_retest_result"} {
			if strings.Contains(p, contract) != strings.Contains(ko, contract) {
				t.Fatalf("translation lost contract %q", contract)
			}
		}
	}
}

func TestBuiltinToolMetadataLanguagePreservesEdits(t *testing.T) {
	en := NewToolSet(nil, "", locale.En).nodeDetail()
	original := en.InputSchema()
	// Simulate a stored English default overriding a runtime Korean tool.
	ko := localizeBuiltinTools([]actool.CoreTool{en}, locale.Ko)[0]
	if ko.Description() == en.Description() {
		t.Fatal("built-in description was not localized")
	}
	if en.Description() != NewToolSet(nil, "", locale.En).nodeDetail().Description() {
		t.Fatal("shared English metadata mutated")
	}
	data, _ := json.Marshal(original)
	var edited map[string]any
	_ = json.Unmarshal(data, &edited)
	props := edited["properties"].(map[string]any)
	props["id"].(map[string]any)["description"] = "user's original custom description"
	custom := DecorateTool(en, "user's original custom tool", edited)
	localized := localizeBuiltinTools([]actool.CoreTool{custom}, locale.Ko)[0]
	if localized.Description() != "user's original custom tool" || localized.InputSchema()["properties"].(map[string]any)["id"].(map[string]any)["description"] != "user's original custom description" {
		t.Fatal("edited metadata changed")
	}
	if localized.Name() != en.Name() {
		t.Fatal("machine tool name changed")
	}
}

func TestAllShippedBuiltinPromptTranslations(t *testing.T) {
	templates := []string{goalsDefaultTmpl, goalsScopeTail, plannerDefaultTmpl, workerDefaultTmpl, mainAgentDefaultTmpl, autoDefaultTmpl, pentestDefaultTmpl, DefaultAssistantPrompt, ReporterDefaultPrompt, RetesterDefaultPrompt, settleWrapUpPrompt, plannerWrapUpDefault, mainAgentWrapUpDefault, genericWrapUpDefault, workerTaskTimeoutDefault, plannerTaskTimeoutDefault}
	if len(templates) != 16 {
		t.Fatal("external agent template inventory changed")
	}
	if err := locale.ValidateTextTranslations(templates); err != nil {
		t.Fatal(err)
	}
	for _, lang := range locale.Languages() {
		for _, english := range templates {
			translated, ok := locale.Raw(lang, english)
			if !ok {
				t.Fatal("fallback masked a missing translation")
			}
			if CanonicalBuiltinPrompt(translated) != english {
				t.Fatalf("%s stock prompt not recognized", lang)
			}
			if CanonicalBuiltinPrompt(translated+" custom edit") != translated+" custom edit" {
				t.Fatal("edited prompt canonicalized")
			}
			for _, contract := range []string{"{{.Goal}}", "set_constraints", "add_task_scope", "report_finding", "update_finding_report", "record_finding_retest_result", "confidence", "evidence_version", "frontier_open=0", "100%", "40%"} {
				if strings.Contains(english, contract) && !strings.Contains(translated, contract) {
					t.Fatalf("%s prompt %.60s lost contract %q", lang, english, contract)
				}
			}
			if strings.Contains(english, "confidence=observed") && (!strings.Contains(translated, "confidence") || !strings.Contains(translated, "observed")) {
				t.Fatalf("%s lost confidence enum", lang)
			}
		}
	}
	old := PromptOverride
	PromptOverride = nil
	defer func() { PromptOverride = old }()
	raw := "user goal / 원문 / {{.Goal}}"
	rendered := renderSystem("planner", plannerDefaultTmpl, PlannerVars{Goal: raw}, locale.ZhHans)
	if !strings.Contains(rendered, "You are") || !strings.Contains(rendered, raw) || strings.Contains(rendered, "%!") {
		t.Fatalf("Chinese interpolation corrupted: %s", rendered)
	}
	if !strings.Contains(outputLanguageInstruction(locale.ZhHans), "Do not translate") {
		t.Fatal("Chinese raw-content boundary missing")
	}
}

func TestToolMetadataAllShippedLanguagesAndReverse(t *testing.T) {
	original := NewToolSet(nil, "", locale.En).nodeDetail()
	for _, lang := range locale.Languages() {
		translated := localizeBuiltinTools([]actool.CoreTool{original}, lang)[0]
		wanted := NewToolSet(nil, "", lang).nodeDetail()
		if translated.Description() != wanted.Description() {
			t.Fatalf("%s wrong stock description", lang)
		}
		translatedSchema, _ := json.Marshal(translated.InputSchema())
		wantedSchema, _ := json.Marshal(wanted.InputSchema())
		if string(translatedSchema) != string(wantedSchema) {
			t.Fatalf("%s wrong schema descriptions", lang)
		}
		reversed := localizeBuiltinTools([]actool.CoreTool{translated}, locale.En)[0]
		reversedSchema, _ := json.Marshal(reversed.InputSchema())
		originalSchema, _ := json.Marshal(original.InputSchema())
		if reversed.Description() != original.Description() || string(reversedSchema) != string(originalSchema) {
			t.Fatal("stock metadata reverse translation failed")
		}
	}
	editedSchema := cloneToolSchema(original.InputSchema())
	property := editedSchema["properties"].(map[string]any)["id"].(map[string]any)
	property["description"] = "user raw custom"
	property["default"] = "user raw default"
	edited := DecorateTool(original, "user raw prose", editedSchema)
	translated := localizeBuiltinTools([]actool.CoreTool{edited}, locale.ZhHans)[0]
	actual := translated.InputSchema()["properties"].(map[string]any)["id"].(map[string]any)
	if translated.Description() != edited.Description() || actual["description"] != property["description"] || actual["default"] != property["default"] {
		t.Fatal("custom fields/defaults modified")
	}
}
