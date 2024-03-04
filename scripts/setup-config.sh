#!/bin/bash

set -e

copy_example_config () {
  if [[ ! -f $1 ]]; then
    echo "copying $1.example to $1"
    cp "$1.example" $1
  fi
}

copy_example_config "max.conf"
copy_example_config "clients.json"
copy_example_config "tests/clients.json"
copy_example_config "saml/tvs/settings.json"
copy_example_config "login_methods.json"
copy_example_config "resources/lang/nl.oidc_error_map.json"
