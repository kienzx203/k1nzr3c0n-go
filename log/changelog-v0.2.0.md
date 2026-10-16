# ScopeWeaver v0.2.0 — Approval usage and safer setup

ScopeWeaver's first release with an outside contribution. Thanks to @xKeNcHii for backporting three upstream ARTEX fixes (#4), credited to their original author.

## Added

- **Approval token usage.** Fallback approval-model calls are recorded separately from planner and worker calls. The approval settings page shows all-time calls, input/output and cache tokens, plus daily input and output tokens for the past 30 days. Days without calls are shown as empty, and past usage stays visible after fallback approval is turned off.
- **Contribution guide.** [CONTRIBUTING.md](../CONTRIBUTING.md) and [CONTRIBUTING.ko.md](../CONTRIBUTING.ko.md) describe requirements, checks, and how pull requests are reviewed. Every PR gets a final human check from the maintainer before merging.
- **Browser smoke test.** A new `e2e` workflow builds the embedded binary and checks setup, login, live events, and approval usage in English and Korean on every PR and after merge.

## Fixed

- **Live events behind a reverse proxy.** Production builds connect to SSE streams on the UI's origin instead of port 8787, so only HTTPS 443 needs to be public. Both READMEs include nginx settings.
- **Authentication fails closed.** Database read errors return 503 instead of being treated as an unset password, so the setup form is hidden during outages. Initial password creation is atomic, so concurrent requests cannot overwrite it. New passwords must have at least 8 characters and at most 72 bytes. Existing passwords keep working.
- **Bounded database connections.** The server limits itself to 32 PostgreSQL connections.

Upstream ARTEX commits: `e2c8a23`, `a951e4a`, `86729b6`. See [provenance](../docs/PROVENANCE.md).

## Downloads

Platform ZIP archives are built for Linux amd64/arm64, macOS amd64/arm64 and Windows amd64, with `SHA256SUMS`. Docker images are built for Linux amd64/arm64 at `ghcr.io/cskwork/scopeweaver`.

## Verification and limitations

- Before merge: all 18 Go packages passed with separate disposable databases, along with 25 frontend tests, the static build, adapter unit tests, the adapter's real-backend E2E test, and the browser smoke test against the built binary. The same checks were repeated on the merged main commit before tagging.
- The inherited `TestGraphOverviewExpandsAssociatedCompanyScope` failure was resolved in `75a706d`; the full backend CI passes.
- Paid model sessions, real target scans, Docker image execution and Windows execution were not performed.
- The unchanged npm dependency set still reports audit findings; dependency upgrades remain separate work.
- Use is subject to the repository's locally isolated research/validation restrictions. This release does not claim production penetration-testing readiness.

See [setup](../README.md) and [verification details](../docs/VERIFICATION.md).
