#!/bin/bash

set -e

#mkdir -p saml/digid/metadata
mkdir -p saml/tvs/metadata

#if [[ ! -f "saml/digid/metadata/idp_metadata.xml" ]]; then
#  echo "Fetching saml digid idp metadata"
#  curl "https://was-preprod1.digid.nl/saml/idp/metadata" --output saml/digid/metadata/idp_metadata.xml
#fi
if [[ ! -f "saml/tvs/metadata/idp_metadata.xml" ]]; then
  echo "Fetching saml tvs idp metadata"
  curl "https://pp2.toegang.overheid.nl/kvs/rd/metadata" --output saml/tvs/metadata/idp_metadata.xml
fi
