package locale

// Profile-form validation messages for native Ollama and per-profile concurrency.
// Keys are the exact English text passed to writeErr. Runtime transport, policy
// and model errors are registered by ollama_backend.go and ollama_server.go;
// keep each key in one file so translations cannot silently override each other.
// The global setting's "zero (unlimited)" key stays in server_engine.go: a profile
// 0 does not mean unlimited, so profile validation uses its own key.
func init() {
	RegisterAll(map[string]map[Lang]string{
		"profile llm_max_concurrent must be zero or greater (0 uses the global setting; native Ollama uses 1)": {
			En:     "profile llm_max_concurrent must be zero or greater (0 uses the global setting; native Ollama uses 1)",
			Ko:     "프로필 llm_max_concurrent는 0 이상이어야 합니다(0이면 전역 설정을 따르고, 네이티브 Ollama는 1을 사용)",
			ZhHans: "配置的 llm_max_concurrent 必须为 0 或更大的值（0 表示沿用全局设置；原生 Ollama 使用 1）",
		},
	})
}
