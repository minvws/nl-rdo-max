#!/bin/bash let them figure IRMA out themself
UNAME=$(uname -a)
if [[ "$UNAME" == *"Darwin"* ]]; then
  if [[ "$UNAME" == *"arm64"* ]]; then
    curl -L "https://github.com/privacybydesign/irmago/releases/download/v0.10.0/irma-master-darwin-arm64" --output irma/darwin-exec
  else
    curl -L "https://github.com/privacybydesign/irmago/releases/download/v0.10.0/irma-master-darwin-amd64" --output irma/darwin-exec
  fi
  chmod +x irma/darwin-exec
else
  UNAME=$(docker run --rm -it alpine uname -a)
  if [[ "$UNAME" == *"aarch64"* ]]; then
    curl -L "https://github.com/privacybydesign/irmago/releases/download/v0.10.0/irma-master-linux-arm64" --output irma/irma-exec
  else
    curl -L "https://github.com/privacybydesign/irmago/releases/download/v0.10.0/irma-master-linux-amd64" --output irma/irma-exec
  fi
  chmod +x irma/irma-exec
  cd irma
  docker build -t irma .
fi
