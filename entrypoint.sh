#!/bin/bash

set -e

[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # load nvm

./scripts/setup-npm.sh

make venv

npm run build

. .venv/bin/activate

exec "$@"
