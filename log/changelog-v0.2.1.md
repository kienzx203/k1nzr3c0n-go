# ScopeWeaver v0.2.1 — Windows reliability and clean dependencies

## Fixed

- **Fresh local installs.** Create the embedded-frontend parent directory before copying the static export. Regression checks cover fresh installs, replacement of stale files, and failed dependency installation or frontend builds. Thanks to @erlendstromsvik for [#9](https://github.com/cskwork/scopeweaver/pull/9).
- **Updated frontend dependencies.** Next.js 16.4.0, React 19.3.0, Tailwind 4.3.3, and the tooling updates from @xKeNcHii in [#7](https://github.com/cskwork/scopeweaver/pull/7) and [#8](https://github.com/cskwork/scopeweaver/pull/8). The merged lockfile retains both the tooling and framework PostCSS requirements.
- **Clean dependency audits.** Remove the unused shadcn CLI dependency and retain its exact 4.12.0 stylesheet locally with its MIT license and provenance. Runtime components remain unchanged. This removes the vulnerable braces dependency chain without a forced downgrade or incompatible override. Future upstream stylesheet changes require updating the vendored file.
- **Windows localization checks.** Normalize path separators before checking the same exact legacy-language exceptions. Unknown or misplaced untranslated text is still rejected.
- **Isolated notification tests.** Cancel the management fixture's server context and close its manager when the test ends, preventing a leftover notifier from consuming later tests' queued deliveries. A deterministic regression verifies both the stale worker's shutdown and delivery by the live fixture.
- **Windows evidence writes.** Commit synced evidence files with a write-through Windows rename instead of attempting to sync a read-only directory handle. Preserve long-path support and surface commit failures; POSIX directory syncing remains unchanged.
- **Python and skill paths.** Skip unusable Python launcher aliases during discovery and fall back to a runnable interpreter. Skill file listings and API paths retain forward slashes on Windows, including nested Unicode names; traversal rejection remains in place.
- **Reliable task fixtures.** Remove test LLM profiles before closing their database, so subsequent task lifecycle tests do not inherit a stale provider. No timeouts or assertions were relaxed.
- **Browser verification.** Place psql options before the connection URL so Windows E2E checks actually execute their SQL. Restore spaces around emphasized English fallback-model helper text and check the complete rendered explanation in both languages.

Existing configured Python interpreter paths are preserved. If an older installation saved an unusable launcher alias, select a runnable interpreter in Settings; automatic discovery applies when the setting is empty.

## Downloads

Platform ZIP archives target Linux amd64/arm64, macOS amd64/arm64, and Windows amd64, with `SHA256SUMS`. Container images target Linux amd64/arm64 at `ghcr.io/cskwork/scopeweaver`.

## Verification

The release is gated on the frontend audit, regression tests and static export; isolated PostgreSQL-backed Go tests; adapter checks; and browser E2E against the embedded binary, before and after merge. See the [verification record](../docs/VERIFICATION.md) for the results and scope.

## 한국어

### 수정

- **새 로컬 설치:** 정적 프런트엔드 산출물을 복사하기 전에 상위 폴더를 생성합니다. 새 설치, 기존 파일 교체, 의존성 설치 및 프런트엔드 빌드 실패를 회귀 테스트로 확인합니다. [#9](https://github.com/cskwork/scopeweaver/pull/9)를 기여한 @erlendstromsvik에게 감사드립니다.
- **프런트엔드 의존성:** @xKeNcHii의 [#7](https://github.com/cskwork/scopeweaver/pull/7), [#8](https://github.com/cskwork/scopeweaver/pull/8)을 통해 Next.js 16.4.0, React 19.3.0, Tailwind 4.3.3과 개발 도구 의존성을 업데이트했습니다. 잠금 파일은 프레임워크와 개발 도구가 각각 요구하는 PostCSS 버전을 유지합니다.
- **의존성 감사:** 사용하지 않는 shadcn CLI 의존성을 제거하고, 4.12.0의 원본 스타일시트를 MIT 라이선스 및 출처와 함께 저장소에 보존합니다. 실행 시 사용하는 컴포넌트는 유지합니다. 강제 다운그레이드나 호환되지 않는 재정의 없이 취약한 braces 의존성 경로를 제거합니다. 향후 업스트림 스타일 변경은 보존한 파일에 반영해야 합니다.
- **Windows 다국어 검사:** 기존의 정확한 호환성 예외를 검사하기 전에 경로 구분자를 정규화합니다. 허용되지 않은 문자열이나 다른 파일의 미번역 텍스트는 계속 거부합니다.
- **알림 테스트 격리:** 관리 API 테스트가 끝나면 서버 컨텍스트를 취소하고 관리자를 닫습니다. 남은 알림 작업자가 후속 테스트의 대기 중 알림을 소비하지 못하도록 하며, 회귀 테스트에서 종료된 작업자의 차단과 정상 작업자의 전송을 함께 확인합니다.
- **Windows 증거 저장:** 읽기 전용 디렉터리 핸들의 동기화 대신, 동기화가 끝난 증거 파일을 Windows 쓰기 완료 보장 옵션으로 이름 변경합니다. 긴 경로를 지원하고 저장 오류를 그대로 반환합니다. POSIX 디렉터리 동기화는 유지합니다.
- **Python과 스킬 경로:** 자동 탐색 시 실행할 수 없는 Python 실행 별칭을 건너뛰고 정상 인터프리터를 선택합니다. 중첩된 유니코드 이름을 포함한 스킬 파일 목록과 API 경로는 Windows에서도 슬래시를 사용하며, 경로 이탈 차단을 유지합니다.
- **작업 테스트 격리:** 데이터베이스를 닫기 전에 테스트용 LLM 프로필을 삭제하여 후속 작업 수명 주기 테스트가 남은 제공자 설정을 상속하지 않게 합니다. 제한 시간이나 검증 조건을 완화하지 않았습니다.
- **브라우저 검증:** psql 옵션을 연결 URL 앞에 배치하여 Windows E2E의 SQL이 실제 실행되도록 합니다. 영어 대체 모델 설명의 강조 구간 사이 공백을 복원하고 두 언어의 전체 표시 문장을 검사합니다.

이미 설정한 Python 인터프리터 경로는 유지합니다. 이전 설치에서 실행할 수 없는 별칭이 저장되었다면 설정에서 정상 인터프리터를 선택하세요. 자동 탐색은 설정이 비어 있을 때 적용됩니다.

### 배포 및 검증

Linux amd64/arm64, macOS amd64/arm64, Windows amd64용 ZIP과 `SHA256SUMS`를 제공합니다. 컨테이너 이미지는 `ghcr.io/cskwork/scopeweaver`의 Linux amd64/arm64를 대상으로 합니다.

병합 전후에 프런트엔드 감사·회귀 검사·정적 빌드, 격리된 PostgreSQL 기반 Go 테스트, 어댑터 검사, 프런트엔드를 내장한 바이너리의 브라우저 E2E를 릴리스 조건으로 확인합니다. 결과와 범위는 [검증 기록](../docs/ko/VERIFICATION.md)을 참고하세요.
