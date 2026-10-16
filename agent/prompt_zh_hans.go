package agent

import (
	_ "embed"
	"encoding/json"
	"github.com/Autumn-27/artex/locale"
)

//go:embed prompt_zh-Hans.json
var zhHansPromptsJSON []byte

func init() {
	var translated map[string]string
	if err := json.Unmarshal(zhHansPromptsJSON, &translated); err != nil {
		panic(err)
	}
	templates := map[string]string{
		"goalsDefaultTmpl":          goalsDefaultTmpl,
		"goalsScopeTail":            goalsScopeTail,
		"plannerDefaultTmpl":        plannerDefaultTmpl,
		"pentestDefaultTmpl":        pentestDefaultTmpl,
		"autoDefaultTmpl":           autoDefaultTmpl,
		"DefaultAssistantPrompt":    DefaultAssistantPrompt,
		"ReporterDefaultPrompt":     ReporterDefaultPrompt,
		"workerDefaultTmpl":         workerDefaultTmpl,
		"mainAgentDefaultTmpl":      mainAgentDefaultTmpl,
		"RetesterDefaultPrompt":     RetesterDefaultPrompt,
		"settleWrapUpPrompt":        settleWrapUpPrompt,
		"plannerWrapUpDefault":      plannerWrapUpDefault,
		"mainAgentWrapUpDefault":    mainAgentWrapUpDefault,
		"genericWrapUpDefault":      genericWrapUpDefault,
		"workerTaskTimeoutDefault":  workerTaskTimeoutDefault,
		"plannerTaskTimeoutDefault": plannerTaskTimeoutDefault,
	}
	if len(translated) != len(templates) {
		panic("Chinese agent prompt count mismatch")
	}
	for name, english := range templates {
		text, ok := translated[name]
		if !ok || text == "" {
			panic("missing Chinese agent prompt: " + name)
		}
		locale.RegisterAll(map[string]map[locale.Lang]string{english: {locale.ZhHans: text}})
	}
}
