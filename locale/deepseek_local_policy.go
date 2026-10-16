package locale

func init() {
	RegisterAll(map[string]map[Lang]string{
		"DeepSeek web search uses a remote LLM and is unavailable while local_llm_only is enabled": {
			En:     "DeepSeek web search uses a remote LLM and is unavailable while local_llm_only is enabled",
			Ko:     "DeepSeek 웹 검색은 원격 LLM을 사용하므로 local_llm_only가 켜져 있을 때 사용할 수 없습니다",
			ZhHans: "DeepSeek 网页搜索使用远程 LLM，启用 local_llm_only 时不可用",
		},
	})
}
