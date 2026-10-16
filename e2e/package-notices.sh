#!/usr/bin/env bash
# Run the real release packaging path with tiny, deterministic fixture executables.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
temp_root="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
fixture="$(mktemp -d "$temp_root/scopeweaver-package.XXXXXX")"
cleanup() {
  case "$fixture" in
    "$temp_root"/scopeweaver-package.*) rm -rf -- "$fixture" ;;
    *) printf 'Refusing cleanup outside packaging fixture: %s\n' "$fixture" >&2 ;;
  esac
}
trap cleanup EXIT
cp "$repo/build.sh" "$repo/THIRD_PARTY_NOTICES.txt" "$fixture/"
mkdir -p "$fixture/bin" "$fixture/server/webui/dist" "$fixture/skills" "$fixture/docs" "$fixture/log" \
  "$fixture/adapters/agent/src" "$fixture/adapters/agent/test"
for name in start.sh start.bat config.example.json README.md README.ko.md LICENSE CHANGELOG.md \
  adapters/agent/package.json adapters/agent/package-lock.json adapters/agent/README.md adapters/agent/pi-extension.js \
  log/changelog-v0.2.1.md skills/SKILL.md docs/guide.md adapters/agent/src/fixture.js adapters/agent/test/fixture.js; do
  printf 'fixture %s\n' "$name" > "$fixture/$name"
done
cat > "$fixture/bin/go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == build && "$CGO_ENABLED" == 0 ]]
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == -o ]]; then printf 'fixture executable %s/%s\n' "$GOOS" "$GOARCH" > "$2"; exit 0; fi
  shift
done
exit 1
SH
chmod +x "$fixture/bin/go"
export PACKAGE_FIXTURE_PYTHON="$(command -v python || command -v python3)"
if ! command -v zip >/dev/null 2>&1; then
  # Git Bash may omit zip; only the fixture dependency is replaced, not build.sh.
  cat > "$fixture/bin/zip" <<'SH'
#!/usr/bin/env bash
"$PACKAGE_FIXTURE_PYTHON" - "$@" <<'PY'
from pathlib import Path
import sys
import zipfile
archive, root = sys.argv[-2:]
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
    for path in Path(root).rglob("*"):
        output.write(path, path.as_posix())
PY
SH
  chmod +x "$fixture/bin/zip"
fi
for language in en ko; do
  (cd "$fixture" && PATH="$fixture/bin:$PATH" SCOPEWEAVER_LANGUAGE="$language" \
    ARTEX_BUILD_VERSION=v0.2.1 ARTEX_SKIP_FRONTEND=1 ARTEX_OUTPUT_DIR="dist-$language" bash ./build.sh --release)
  "$PACKAGE_FIXTURE_PYTHON" - "$fixture/dist-$language" "$repo/THIRD_PARTY_NOTICES.txt" <<'PY'
import hashlib
from pathlib import Path
import sys
import zipfile
directory, notice = map(Path, sys.argv[1:])
archives = sorted(directory.glob("*.zip"))
assert len(archives) == 5, archives
for path in archives:
    with zipfile.ZipFile(path) as archive:
        root = path.stem
        assert archive.read(f"{root}/THIRD_PARTY_NOTICES.txt") == notice.read_bytes()
        target = root.removeprefix("scopeweaver-0.2.1-").replace("-", "/")
        binary = "scopeweaver.exe" if target.startswith("windows/") else "scopeweaver"
        assert archive.read(f"{root}/{binary}") == f"fixture executable {target}\n".encode()
for line in (directory / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split()
    name = name.removeprefix("*")
    assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest
print("PASS: all five archives contain exact notice and unchanged fixture executables")
PY
done
