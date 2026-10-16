# ScopeWeaver v0.4.0 — Native Ollama and flexible cloud providers

## Added

- **Native Ollama profiles.** Use Ollama's `/api/chat` with streaming, tool calls and model-supported thinking. Local Ollama needs no API key; reverse proxies can use an optional Bearer token. Three new-profile templates cover the same machine, a Docker host bridge and the optional Compose service. See [#22](https://github.com/cskwork/scopeweaver/pull/22) and the [provider guide](../docs/llm-providers.md).
- **Installed-model selection.** Selecting an Ollama template or changing a new profile's format to Ollama reads the selected server's installed models, preferring declared tool support. It never assumes a model tag is installed. Discovery leaves the model blank while pending, and keeps it blank with an error on failure or an empty list. Manual model and connection edits take priority over late responses. Selection does not download or run a model, save, or activate a profile.
- **Ollama context and diagnostics.** Native profiles request a 32,768-token context by default, a 30-minute keep-alive, a 4,096-token output limit and one in-flight request per server. Connection testing reports context allocation, tool-call results, load time and generation speed. Installed-model lists show available capability metadata.
- **Local execution controls.** Native model prewarm checks declared tool support and shares the server's concurrency gate. Small contexts receive earlier compaction and bounded tool text. Ollama approval judges default to a 60-second timeout and ask the user when judging fails, unless explicitly configured otherwise.
- **Optional local-only LLM policy.** The default remains off. Enabling it restricts ScopeWeaver's LLM HTTP calls to local or explicitly trusted addresses, checks redirects, and rejects profile proxies. The bundled optional Ollama Compose service disables Ollama cloud forwarding.

## Fixed

- Ollama selection clears an unsaved cloud API key before discovery; cloud templates continue to preserve entered credentials.
- Native model-not-found diagnostics preserve the exact model tag in the suggested server-side `ollama pull` command. No model is pulled automatically.
- Empty environment-variable overrides, local key status and connection-test concurrency use the native-provider rules consistently.
- Startup configuration preserves Anthropic/OpenAI provider-key authentication for local gateways. An explicit blank generic key still suppresses inherited credentials; native Ollama never inherits cloud keys.
- A blank-key connection test can reuse the active local gateway key when its format, normalized endpoint and proxy match. Different local targets and native Ollama remain isolated; saving a new blank-key profile does not import credentials.

## Compatibility and limits

Anthropic, OpenAI Chat Completions and OpenAI Responses remain available. Custom endpoints, proxies, session headers, retries and rate settings remain configurable. Local OpenAI-compatible servers can use keyless profiles; public cloud endpoints still require credentials. Existing profiles retain their stored model when opened.

Declared `tools` support is not proof that a model will call tools correctly or finish autonomous tasks. Run **Test connection** on the actual model and assess it for the intended work; small local models are not established as reliable main agents. Hardware and model examples are guidance, not benchmarks or automatic choices.

The local-only policy covers ScopeWeaver's LLM HTTP calls, not all application or target traffic. ScopeWeaver cannot control an Ollama server's own outbound behavior. Set `OLLAMA_NO_CLOUD=1` on host or remote Ollama servers when work must stay inside your network. Docker on macOS cannot use the Apple GPU; use native host Ollama for GPU acceleration.

## Verification

See [verification evidence and limitations](../docs/VERIFICATION.md). Paid cloud accounts and autonomous task reliability remain outside the verified scope.

## 한국어

### 추가

- **Ollama 네이티브 프로필:** Ollama의 `/api/chat`으로 스트리밍, 도구 호출, 모델이 지원하는 추론을 사용합니다. 로컬 Ollama에는 API 키가 필요 없으며, 리버스 프록시에는 선택적으로 Bearer 토큰을 쓸 수 있습니다. 같은 컴퓨터, Docker 호스트 브리지, 선택형 Compose 서비스용 새 프로필 템플릿을 제공합니다. [#22](https://github.com/cskwork/scopeweaver/pull/22)와 [제공자 안내](../docs/ko/llm-providers.md)를 참고하세요.
- **설치된 모델 자동 선택:** Ollama 템플릿을 선택하거나 새 프로필의 형식을 Ollama로 바꾸면 해당 서버에 설치된 모델을 조회하고 도구 호출 지원을 선언한 모델을 우선 선택합니다. 특정 모델 태그가 설치되어 있다고 가정하지 않습니다. 조회 중에는 모델 칸을 비우고, 실패하거나 목록이 비어 있으면 오류와 함께 빈 상태로 둡니다. 모델이나 연결 필드를 직접 수정하면 늦게 도착한 응답이 덮어쓰지 않습니다. 선택만으로 모델을 내려받거나 실행하거나 프로필을 저장·활성화하지 않습니다.
- **Ollama 문맥과 진단:** 기본값은 문맥 32,768토큰, 모델 유지 30분, 출력 한도 4,096토큰, 서버당 동시 요청 1개입니다. 연결 테스트에서 문맥 할당, 도구 호출 결과, 로드 시간, 생성 속도를 확인할 수 있습니다. 설치된 모델 목록에는 조회된 기능 정보도 표시합니다.
- **로컬 실행 제어:** 네이티브 모델 예열에서 도구 호출 지원 선언을 확인하며 서버의 동시 요청 제한을 함께 사용합니다. 작은 문맥은 더 일찍 압축하고 도구 텍스트 크기를 제한합니다. 별도 설정이 없으면 Ollama 승인 판정의 제한 시간은 60초이며 실패하면 사용자에게 확인합니다.
- **선택형 로컬 전용 LLM 정책:** 기본값은 꺼짐입니다. 켜면 ScopeWeaver의 LLM HTTP 호출을 로컬 또는 명시적으로 신뢰한 주소로 제한하고, 리디렉션을 검사하며 프로필 프록시를 거부합니다. 선택형 번들 Ollama Compose 서비스는 Ollama 클라우드 전달을 끕니다.

### 수정

- Ollama를 선택하면 조회 전에 저장하지 않은 클라우드 API 키를 지웁니다. 클라우드 템플릿은 입력한 자격 증명을 계속 유지합니다.
- 네이티브 모델이 없을 때 안내하는 서버 측 `ollama pull` 명령에 정확한 모델 태그를 보존합니다. 자동으로 모델을 내려받지는 않습니다.
- 빈 환경 변수의 덮어쓰기, 로컬 키 상태, 연결 테스트 동시 요청 제한에 네이티브 제공자 규칙을 일관되게 적용합니다.
- 시작 설정에서 로컬 게이트웨이의 Anthropic·OpenAI 제공자 키 인증을 유지합니다. 공통 키를 명시적으로 비워 두면 기존 자격 증명을 사용하지 않으며, 네이티브 Ollama는 클라우드 키를 가져오지 않습니다.
- 키를 비운 연결 테스트는 형식, 정규화된 엔드포인트, 프록시가 활성 로컬 게이트웨이와 같으면 활성 키를 사용할 수 있습니다. 다른 로컬 대상과 네이티브 Ollama에는 활성 키를 전달하지 않으며, 새 프로필의 키를 비워 저장해도 자격 증명을 가져오지 않습니다.

### 호환성과 한계

Anthropic, OpenAI Chat Completions, OpenAI Responses를 계속 사용할 수 있습니다. 사용자 지정 엔드포인트, 프록시, 세션 헤더, 재시도, 속도 설정도 유지합니다. 로컬 OpenAI 호환 서버는 키 없는 프로필을 쓸 수 있으며, 공용 클라우드 엔드포인트에는 자격 증명이 필요합니다. 기존 프로필을 열 때는 저장된 모델을 유지합니다.

`tools` 지원 선언만으로 실제 도구 호출이나 자율 작업 완료가 보장되지는 않습니다. 실제 사용할 모델에서 **연결 테스트**를 실행하고 용도에 맞게 평가하세요. 작은 로컬 모델은 신뢰할 수 있는 주 에이전트로 검증되지 않았습니다. 하드웨어와 모델 예시는 성능 측정값이나 자동 선택 기준이 아닙니다.

로컬 전용 정책은 ScopeWeaver의 LLM HTTP 호출에만 적용하며 전체 앱이나 대상 트래픽을 제한하지 않습니다. ScopeWeaver는 Ollama 서버 자체의 외부 통신을 제어할 수 없습니다. 작업이 내부 네트워크에 머물러야 한다면 호스트나 원격 Ollama 서버에 `OLLAMA_NO_CLOUD=1`을 설정하세요. macOS의 Docker에서는 Apple GPU를 사용할 수 없으므로 GPU 가속이 필요하면 호스트에서 Ollama를 직접 실행하세요.

### 검증

[검증 증거와 한계](../docs/ko/VERIFICATION.md)를 참고하세요. 유료 클라우드 계정과 자율 작업의 신뢰성은 검증 범위에 포함되지 않습니다.

---

[Compare v0.3.1...v0.4.0](https://github.com/cskwork/scopeweaver/compare/v0.3.1...v0.4.0)
