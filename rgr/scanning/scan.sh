#!/usr/bin/env bash
# Автоматизований аналіз (SAST + SCA + секрети) для джерела $1 у каталог $2.
# Приклад: scanning/scan.sh upstream reports/before
set -u
SRC="$(cd "${1:-upstream}" && pwd)"; OUT="${2:-reports/out}"; mkdir -p "$OUT"
HERE="$(cd "$(dirname "$0")" && pwd)"
echo "[SAST] Semgrep"
docker run --rm -v "$SRC":/src -w /src semgrep/semgrep:latest semgrep \
  --config p/javascript --config p/typescript --config p/nodejs --config p/jwt \
  --json --output /src/_sg.json routes lib models data server.ts app.ts >/dev/null 2>&1
mv "$SRC/_sg.json" "$OUT/semgrep.json"
echo "[секрети] gitleaks"
docker run --rm -v "$SRC":/src -v "$HERE/gitleaks.toml":/gl.toml zricethezav/gitleaks:latest \
  detect --source /src --no-git --config /gl.toml --report-format json --report-path /src/_gl.json >/dev/null 2>&1 || true
mv "$SRC/_gl.json" "$OUT/gitleaks.json"
echo "[SCA] npm audit + Trivy"
( cd "$SRC" && npm install --package-lock-only --package-lock=true --no-audit --no-fund >/dev/null 2>&1 && npm audit --omit=dev --json > "$OUT/npm_audit.json" 2>/dev/null || true )
docker run --rm -e TRIVY_NO_PROGRESS=1 -v "$SRC":/src aquasec/trivy:latest fs --quiet \
  --scanners vuln --severity HIGH,CRITICAL --format json --output /src/_tv.json /src/package-lock.json >/dev/null 2>&1 || true
mv "$SRC/_tv.json" "$OUT/trivy.json" 2>/dev/null || true
echo "Готово -> $OUT"
