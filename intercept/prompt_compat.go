package intercept

// IsDefaultJudgePrompt reports whether the configured LLM-judge prompt is the
// stock bundled one (i.e. the user has not customized it).
func IsDefaultJudgePrompt(prompt string) bool {
	return prompt == "" || prompt == DefaultJudgePrompt
}
