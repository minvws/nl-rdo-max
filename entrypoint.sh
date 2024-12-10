#!/bin/bash

set -e

./scripts/setup-npm.sh

make venv

npm run build

. .venv/bin/activate

exec "$@"
