package locale

func init() {
	RegisterAll(map[string]map[Lang]string{
		"Ollama model %q does not support tool calling": {
			En: "Ollama model %q does not support tool calling", Ko: "Ollama 모델 %q은(는) 도구 호출을 지원하지 않습니다", ZhHans: "Ollama 模型 %q 不支持工具调用",
		},
		"invalid local LLM allowed CIDR %q: %w": {
			En: "invalid local LLM allowed CIDR %q: %w", Ko: "허용된 로컬 LLM CIDR %q이(가) 올바르지 않습니다: %w", ZhHans: "本地 LLM 允许的 CIDR %q 无效：%w",
		},
	})
}
