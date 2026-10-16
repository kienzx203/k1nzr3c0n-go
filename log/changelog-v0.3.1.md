# ScopeWeaver v0.3.1 — Simplified Chinese and extensible locales

## Added

- **Simplified Chinese interface.** Choose 简体中文 (`zh-Hans`) from the language selector. The interface, server messages, stock agent and report metadata, and calendar formatting are fully translated. English remains the default, and the existing English and Korean experience is unchanged. Language tags `zh`, `zh-CN`, `zh-SG`, and `zh-Hans-*` match Simplified Chinese. Traditional Chinese tags such as `zh-Hant`, `zh-TW`, and `zh-HK` are not supported yet and do not match Simplified Chinese. See [#19](https://github.com/cskwork/scopeweaver/pull/19).
- **Extensible locale registry.** Frontend and backend now share one locale declaration, so a new language can be added by registering a complete catalog. Existing `Register` and `RegisterAll` calls remain compatible. See the [i18n guide](../web/src/i18n/README.md).

## Fixed

- **Informational report headings.** Generated reports show the localized label for informational findings. Empty and custom severity values keep their existing behavior.
- **Docker frontend build.** The Docker frontend build now receives the shared locale declaration, fixing the missing `locale/definitions.json` import.

## Compatibility

Switching languages preserves your drafts and custom content, and your language selection persists across reloads. Raw evidence, history, and identifiers stay as recorded.

This release is the first phase of [#15](https://github.com/cskwork/scopeweaver/issues/15). Traditional Chinese, Japanese, and Spanish are planned, and the issue remains open.

## Downloads

Platform ZIP archives target Linux amd64/arm64, macOS amd64/arm64, and Windows amd64, with `SHA256SUMS`.

Container images target Linux amd64/arm64 at `ghcr.io/cskwork/scopeweaver`.

## Verification

All 5,021 English/Simplified Chinese message pairs (3,113 frontend and 1,908 backend) were reviewed. Pull request checks, merged-main CI, and browser E2E checks passed, and the Chinese interface was checked manually in a running build. The Docker frontend build failure was reproduced, and a clean Docker frontend build passes with the fix. Native-speaker review and live LLM runs in Chinese have not been verified. Release archive contents, platform execution, and container execution require separate verification.

## 한국어

### 추가

- **중국어 간체 화면:** 언어 선택기에서 简体中文(`zh-Hans`)을 고를 수 있습니다. 화면, 서버 메시지, 기본 제공 에이전트 및 보고서 메타데이터, 달력 형식이 모두 번역되었습니다. 기본 언어는 계속 영어이며 기존 영어·한국어 사용 경험은 그대로입니다. `zh`, `zh-CN`, `zh-SG`, `zh-Hans-*` 언어 태그는 중국어 간체로 연결됩니다. `zh-Hant`, `zh-TW`, `zh-HK` 같은 중국어 번체 태그는 아직 지원하지 않으며 중국어 간체로 연결되지 않습니다. [#19](https://github.com/cskwork/scopeweaver/pull/19)를 참고하세요.
- **확장 가능한 로케일 레지스트리:** 프런트엔드와 백엔드가 하나의 로케일 선언을 공유하므로, 완성된 카탈로그를 등록하여 새 언어를 추가할 수 있습니다. 기존 `Register`, `RegisterAll` 호출은 그대로 호환됩니다. [i18n 가이드](../web/src/i18n/README.ko.md)를 참고하세요.

### 수정

- **정보성 보고서 제목:** 생성된 보고서에서 정보성 발견 사항의 레이블이 화면 언어에 맞게 표시됩니다. 비어 있거나 사용자 지정한 심각도 값은 기존 동작을 유지합니다.
- **Docker 프런트엔드 빌드:** Docker 프런트엔드 빌드에 공유 로케일 선언이 포함되어, `locale/definitions.json`을 가져오지 못하던 문제가 해결되었습니다.

### 호환성

언어를 바꿔도 임시 저장본과 사용자 지정 콘텐츠는 유지되며, 선택한 언어는 새로고침 후에도 유지됩니다. 원본 증거, 기록, 식별자도 기록된 그대로 유지됩니다.

이번 릴리스는 [#15](https://github.com/cskwork/scopeweaver/issues/15)의 첫 단계입니다. 중국어 번체, 일본어, 스페인어는 이후 지원할 예정이며 이 이슈는 계속 열려 있습니다.

### 다운로드

ZIP 아카이브는 Linux amd64/arm64, macOS amd64/arm64, Windows amd64를 대상으로 하며 `SHA256SUMS`를 포함합니다.

컨테이너 이미지는 `ghcr.io/cskwork/scopeweaver`의 Linux amd64/arm64를 대상으로 합니다.

### 검증

영어·중국어 간체 메시지 쌍 5,021개(프런트엔드 3,113개, 백엔드 1,908개)를 모두 검토했습니다. 풀 리퀘스트 검사, 병합된 main의 CI와 브라우저 E2E 검사를 통과했으며, 실행 중인 빌드에서 중국어 화면을 직접 확인했습니다. Docker 프런트엔드 빌드 실패를 재현했고, 수정 후 깨끗한 Docker 프런트엔드 빌드가 통과했습니다. 원어민 검토와 중국어 실제 LLM 실행은 검증하지 않았습니다. 릴리스 아카이브 내용, 플랫폼별 실행, 컨테이너 실행은 별도로 검증해야 합니다.

---

[Compare v0.3.0...v0.3.1](https://github.com/cskwork/scopeweaver/compare/v0.3.0...v0.3.1)
