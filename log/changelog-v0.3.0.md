# ScopeWeaver v0.3.0 — Asset exports and LLM concurrency

## Added

- **CSV and JSON asset exports.** Download selected assets or every asset matching the current filter from the Assets page. The export API also supports all assets. Exports preserve company, task, type, and search scope without pagination or a 50-row cap. CSV headers follow the English or Korean interface language, and service/endpoint values retain their full URLs. Thanks to @erlendstromsvik for [#17](https://github.com/cskwork/scopeweaver/pull/17).
- **Maximum concurrent LLM requests.** Set `llm_max_concurrent` in System Settings to cap simultaneous requests per LLM profile, shared across that profile's agents. The default, `0`, means unlimited. Saving rebuilds providers so the setting applies to the next request. This is separate from the request rate limit. Thanks to @erlendstromsvik for [#14](https://github.com/cskwork/scopeweaver/pull/14).

## Fixed

- **Daily token chart.** Stack cache-miss input, cache-read, and output tokens without counting cache reads twice. Restore the input bar's fill so all three parts remain visible. Thanks to @erlendstromsvik for [#16](https://github.com/cskwork/scopeweaver/pull/16).
- **Third-party notices in release packages.** Include `THIRD_PARTY_NOTICES.txt` in ZIP packages and container images. The existing-release repair workflow reads raw platform manifests when checking image contents. See [#11](https://github.com/cskwork/scopeweaver/pull/11) and [#12](https://github.com/cskwork/scopeweaver/pull/12).

## Downloads

Platform ZIP archives target Linux amd64/arm64, macOS amd64/arm64, and Windows amd64, with `SHA256SUMS`.

Container images target Linux amd64/arm64 at `ghcr.io/cskwork/scopeweaver`.

## Verification

Merged-main CI and browser E2E checks passed. Release archive contents, platform execution, and container execution require separate verification.

## 한국어

### 추가

- **CSV 및 JSON 자산 내보내기:** 자산 화면에서 선택한 자산 또는 현재 필터에 맞는 모든 자산을 내려받을 수 있습니다. 내보내기 API는 전체 자산도 지원합니다. 회사, 작업, 자산 유형, 검색 범위를 유지하며 페이지 구분이나 50개 제한 없이 내보냅니다. CSV 열 제목은 영어 또는 한국어 화면 언어를 따르고, 서비스·엔드포인트 값은 전체 URL을 유지합니다. [#17](https://github.com/cskwork/scopeweaver/pull/17)을 기여한 @erlendstromsvik에게 감사드립니다.
- **최대 동시 LLM 요청 수:** 시스템 설정의 `llm_max_concurrent`로 LLM 프로필마다 동시 요청 수를 제한합니다. 해당 프로필의 에이전트들이 제한을 공유하며, 기본값 `0`은 무제한입니다. 저장하면 프로바이더를 재구성하여 다음 요청부터 적용합니다. 요청 속도 제한과는 별도의 설정입니다. [#14](https://github.com/cskwork/scopeweaver/pull/14)를 기여한 @erlendstromsvik에게 감사드립니다.

### 수정

- **일별 토큰 차트:** 캐시 미적중 입력, 캐시 읽기, 출력 토큰을 누적 표시하여 캐시 읽기 토큰의 중복 집계를 없앴습니다. 입력 막대의 채우기 색도 복원하여 세 구간이 모두 보이도록 했습니다. [#16](https://github.com/cskwork/scopeweaver/pull/16)을 기여한 @erlendstromsvik에게 감사드립니다.
- **릴리스 패키지의 서드파티 고지:** ZIP 패키지와 컨테이너 이미지에 `THIRD_PARTY_NOTICES.txt`를 포함합니다. 기존 릴리스 복구 워크플로는 이미지 내용 확인 시 플랫폼별 원본 매니페스트를 읽습니다. [#11](https://github.com/cskwork/scopeweaver/pull/11), [#12](https://github.com/cskwork/scopeweaver/pull/12)를 참고하세요.

### 다운로드

ZIP 아카이브는 Linux amd64/arm64, macOS amd64/arm64, Windows amd64를 대상으로 하며 `SHA256SUMS`를 포함합니다.

컨테이너 이미지는 `ghcr.io/cskwork/scopeweaver`의 Linux amd64/arm64를 대상으로 합니다.

### 검증

병합된 main의 CI와 브라우저 E2E 검사를 통과했습니다. 릴리스 아카이브 내용, 플랫폼별 실행, 컨테이너 실행은 별도로 검증해야 합니다.

---

[Compare v0.2.1...v0.3.0](https://github.com/cskwork/scopeweaver/compare/v0.2.1...v0.3.0)
