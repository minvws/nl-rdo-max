#!/usr/bin/env bash

set -e

if [ "$INSTALL_NPM_ASSETS" == "true" ]; then
    echo "Setup NPM..."
    ./scripts/setup-npm.sh

    echo "NPM build..."
    npm run build
fi

. .venv/bin/activate

exec "$@"
