package intercept

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
	templates := map[string]string{"JudgeContextBoundary": JudgeContextBoundary, "JudgeOutputContract": JudgeOutputContract, "DefaultJudgePrompt": DefaultJudgePrompt}
	if len(translated) != len(templates) {
		panic("Chinese judge prompt count mismatch")
	}
	for name, english := range templates {
		text, ok := translated[name]
		if !ok || text == "" {
			panic("missing Chinese judge prompt: " + name)
		}
		locale.RegisterAll(map[string]map[locale.Lang]string{english: {locale.ZhHans: text}})
	}
}
