#!/usr/bin/env bash

set -e

# Set project directory if unset, positionally (chdir) stable.
if [[ -z "$PROJECT_DIR" ]]; then
  PROJECT_DIR="$(cd "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 ; pwd -P)"
fi
echo "Using PROJECT_DIR=$PROJECT_DIR"

# Check if we even have a need for a registry block and token.
# I.e., one could have done npm uninstall $PRIVATE_PACKAGE before
# running this script, in which case, it would not care about the
# existence of any configuration of npm.pkg.github.com in .npmrc.
PRIVATE_PACKAGE="@minvws/nl-rdo-rijksoverheid-ui-theme"
if grep -q "\"$PRIVATE_PACKAGE\":" "package.json"; then

  echo "Package $PRIVATE_PACKAGE exists in package.json"
  echo "Making sure it is referenced in app.js, app.scss.."
  sed -E -i.orig "s|^//(import ['\"]@minvws/)|\1|g" "resources/js/app.js"
  sed -E -i.orig "s|^//(@import ['\"]@minvws/)|\1|g" "resources/css/app.scss"

  echo "Checking and/or enabling npm.pkg.github.com configuration.."

  # Determine NPMRC_FILE location.
  if [[ -n "$RUNNER_TEMP"  && -f "$RUNNER_TEMP/.npmrc" ]]; then
      NPMRC_FILE="$RUNNER_TEMP/.npmrc"
  elif [[ -f "$PROJECT_DIR/.npmrc" ]]; then
      NPMRC_FILE="$PROJECT_DIR/.npmrc"
  else
      NPMRC_FILE="$HOME/.npmrc"
      [[ ! -f "$NPMRC_FILE" ]] && touch "$NPMRC_FILE"
  fi

  # Text block we want to check for and add if missing.
  NPMRC_BLOCK='@minvws:registry=https://npm.pkg.github.com/\n//npm.pkg.github.com/:_authToken='
  if ! grep -qzoP "$NPMRC_BLOCK" "$NPMRC_FILE"; then
      if [ -z "$GITHUB_TOKEN" ]; then
          echo -n "GITHUB_TOKEN not set, please enter your GitHub token string: "
          read GITHUB_TOKEN
      fi

      if [ -z "$GITHUB_TOKEN" ]; then
          echo "GITHUB_TOKEN is required but not set, exiting script."
          exit 1
      fi

      echo -e "$NPMRC_BLOCK$GITHUB_TOKEN" >> "$NPMRC_FILE"
  fi
else
  # Make sure NPMRC_FILE exists, so secret mount can work.
  NPMRC_FILE="$HOME/.npmrc"
  [[ ! -f "$NPMRC_FILE" ]] && touch "$NPMRC_FILE"

  echo "Package $PRIVATE_PACKAGE does not exist in package.json"
  echo "Making sure it is not referenced in app.js, app.scss.."
  sed -i.orig "s|^import ['\"]@minvws/|//&|g" "resources/js/app.js"
  sed -i.orig "s|^@import ['\"]@minvws/|//&|g" "resources/css/app.scss"
fi

# Run npm ci command.
echo "Running npm ci command.."
npm ci --ignore-scripts
