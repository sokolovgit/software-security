#!/usr/bin/env bash
# Відтворення середовища РГР: клонує ціль на позначці v20.4.0 у upstream/,
# застосовує виправлення з fixes/ і збирає серверну частину.
set -euo pipefail
cd "$(dirname "$0")"
REPO=https://github.com/juice-shop/juice-shop
TAG=v20.4.0
if [ ! -d upstream ]; then
  git clone --depth 1 --branch "$TAG" "$REPO" upstream
fi
cd upstream
# чистий стан позначки
git stash -u >/dev/null 2>&1 || true
npm install --no-audit --no-fund
npm install --no-audit --no-fund bcryptjs
# застосувати всі виправлення РГР
git apply --3way ../fixes/all-fixes.patch || patch -p1 < ../fixes/all-fixes.patch
npm run build:server
echo "Готово. Запуск: PORT=3001 NODE_ENV=unsafe node build/app.js"
