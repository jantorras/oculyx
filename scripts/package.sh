#!/usr/bin/env bash
# Builds the release package: oculyx.tar.gz (+ .sha256) in the repository root.
# Contents: server, agent, the built web UI, lockfile and deploy scripts. No node_modules.
set -euo pipefail
cd "$(dirname "$0")/.."

npm run build:web
rm -f oculyx.tar.gz oculyx.tar.gz.sha256
tar -czf oculyx.tar.gz \
  --exclude=node_modules --exclude='*.log' \
  server agent web/dist web/package.json package.json package-lock.json LICENSE README.md deploy
sha256sum oculyx.tar.gz > oculyx.tar.gz.sha256
ls -lh oculyx.tar.gz
