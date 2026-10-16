package locale

func init() {
	RegisterAll(map[string]map[Lang]string{
		"ollama: HTTP 404: model %s was not found; run ollama pull %s: %s":                                                         {En: "ollama: HTTP 404: model %s was not found; run ollama pull %s: %s", Ko: "ollama: HTTP 404: 모델 %s을 찾을 수 없습니다. ollama pull %s을 실행하세요: %s", ZhHans: "ollama：HTTP 404：未找到模型 %s；请运行 ollama pull %s：%s"},
		"ollama: HTTP %d: native endpoint unavailable; choose the OpenAI format for a compatible server or check the base URL: %s": {En: "ollama: HTTP %d: native endpoint unavailable; choose the OpenAI format for a compatible server or check the base URL: %s", Ko: "ollama: HTTP %d: 네이티브 엔드포인트를 사용할 수 없습니다. 호환 서버는 OpenAI 형식을 선택하거나 기본 URL을 확인하세요: %s", ZhHans: "ollama：HTTP %d：原生端点不可用；对于兼容服务器，请选择 OpenAI 格式或检查基本 URL：%s"},
		"ollama: connection failed: %w":                                                   {En: "ollama: connection failed: %w", Ko: "ollama: 연결 실패: %w", ZhHans: "ollama：连接失败：%w"},
		"ollama: invalid stream response: %w":                                             {En: "ollama: invalid stream response: %w", Ko: "ollama: 잘못된 스트림 응답: %w", ZhHans: "ollama：无效的流响应：%w"},
		"local_llm_only: proxies are not allowed":                                         {En: "local_llm_only: proxies are not allowed", Ko: "local_llm_only: 프록시를 사용할 수 없습니다", ZhHans: "local_llm_only：不允许使用代理"},
		"llm: invalid proxy: %w":                                                          {En: "llm: invalid proxy: %w", Ko: "llm: 잘못된 프록시: %w", ZhHans: "llm：无效的代理：%w"},
		"llm: proxy requires a host":                                                      {En: "llm: proxy requires a host", Ko: "llm: 프록시에 호스트가 필요합니다", ZhHans: "llm：代理必须包含主机"},
		"local_llm_only: invalid allowed CIDR %q: %w":                                     {En: "local_llm_only: invalid allowed CIDR %q: %w", Ko: "local_llm_only: 잘못된 허용 CIDR %q: %w", ZhHans: "local_llm_only：无效的允许 CIDR %q：%w"},
		"local_llm_only: no addresses for %s":                                             {En: "local_llm_only: no addresses for %s", Ko: "local_llm_only: %s의 주소를 찾을 수 없습니다", ZhHans: "local_llm_only：未找到 %s 的地址"},
		"local_llm_only: LLM destination %s (%s) is not local or allowlisted":             {En: "local_llm_only: LLM destination %s (%s) is not local or allowlisted", Ko: "local_llm_only: LLM 대상 %s (%s)은 로컬 또는 허용 목록에 없습니다", ZhHans: "local_llm_only：LLM 目标 %s (%s) 不是本地地址且不在允许列表中"},
		"llm: API key required for non-local compatible endpoint":                         {En: "llm: API key required for non-local compatible endpoint", Ko: "llm: 로컬이 아닌 호환 엔드포인트에는 API 키가 필요합니다", ZhHans: "llm：非本地兼容端点需要 API 密钥"},
		"ollama: invalid base URL %q":                                                     {En: "ollama: invalid base URL %q", Ko: "ollama: 잘못된 기본 URL %q", ZhHans: "ollama：无效的基本 URL %q"},
		"ollama: HTTP client is required":                                                 {En: "ollama: HTTP client is required", Ko: "ollama: HTTP 클라이언트가 필요합니다", ZhHans: "ollama：必须提供 HTTP 客户端"},
		"ollama: HTTP %d: %s":                                                             {En: "ollama: HTTP %d: %s", Ko: "ollama: HTTP %d: %s", ZhHans: "ollama：HTTP %d：%s"},
		"ollama: invalid response: %w":                                                    {En: "ollama: invalid response: %w", Ko: "ollama: 잘못된 응답: %w", ZhHans: "ollama：无效的响应：%w"},
		"ollama: %s":                                                                      {En: "ollama: %s", Ko: "ollama: %s", ZhHans: "ollama：%s"},
		"ollama: model warm-up returned an incomplete response":                           {En: "ollama: model warm-up returned an incomplete response", Ko: "ollama: 모델 예열 응답이 완료되지 않았습니다", ZhHans: "ollama：模型预热返回了不完整的响应"},
		"ollama: diagnostic completion was incomplete":                                    {En: "ollama: diagnostic completion was incomplete", Ko: "ollama: 진단 응답이 완료되지 않았습니다", ZhHans: "ollama：诊断响应未完成"},
		"ollama: model %s does not declare tools capability; select a tool-capable model": {En: "ollama: model %s does not declare tools capability; select a tool-capable model", Ko: "ollama: 모델 %s에 도구 지원 기능이 없습니다. 도구 호출을 지원하는 모델을 선택하세요", ZhHans: "ollama：模型 %s 未声明工具能力；请选择支持工具调用的模型"},
		"ollama: model %s did not execute the diagnostic tool call":                       {En: "ollama: model %s did not execute the diagnostic tool call", Ko: "ollama: 모델 %s이 진단 도구 호출을 수행하지 않았습니다", ZhHans: "ollama：模型 %s 未执行诊断工具调用"},
		"ollama: requested context %d was not verified in /api/ps (reported %d)":          {En: "ollama: requested context %d was not verified in /api/ps (reported %d)", Ko: "ollama: 요청한 문맥 크기 %d을 /api/ps에서 확인하지 못했습니다 (보고된 크기 %d)", ZhHans: "ollama：未在 /api/ps 中确认请求的上下文 %d（报告值为 %d）"},
		"ollama: invalid arguments for tool %s":                                           {En: "ollama: invalid arguments for tool %s", Ko: "ollama: 도구 %s의 인수가 잘못되었습니다", ZhHans: "ollama：工具 %s 的参数无效"},
		"ollama: unsupported message block type %q":                                       {En: "ollama: unsupported message block type %q", Ko: "ollama: 지원하지 않는 메시지 블록 형식 %q", ZhHans: "ollama：不支持的消息块类型 %q"},
		"ollama: incomplete response (missing done)":                                      {En: "ollama: incomplete response (missing done)", Ko: "ollama: 불완전한 응답 (done 누락)", ZhHans: "ollama：响应不完整（缺少 done）"},
		"ollama: incomplete stream (missing done)":                                        {En: "ollama: incomplete stream (missing done)", Ko: "ollama: 불완전한 스트림 (done 누락)", ZhHans: "ollama：流不完整（缺少 done）"},
		"ollama: model returned no content":                                               {En: "ollama: model returned no content", Ko: "ollama: 모델이 내용을 반환하지 않았습니다", ZhHans: "ollama：模型未返回任何内容"},
	})
}
