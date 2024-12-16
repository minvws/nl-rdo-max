#!/usr/bin/env bash

set -e

SECRETS_DIR=secrets
SAML_DIR=saml

create_key_pair () {
  echo "generating keypair and certificate $1/$2 with CN:$3"
  openssl genrsa -out $1/$2.key 2048
  openssl rsa -in $1/$2.key -pubout > $1/$2.pub
  openssl req -new -sha256 \
    -key $1/$2.key \
    -subj "/C=US/CN=$3" \
    -out $1/$2.csr
  openssl x509 -req -days 500 -sha256 \
    -in $1/$2.csr \
    -CA $SECRETS_DIR/cacert.crt \
    -CAkey $SECRETS_DIR/cacert.key \
    -CAcreateserial \
    -out $1/$2.crt
  rm $1/$2.csr
}

mkdir -p ./$SECRETS_DIR/userinfo
mkdir -p ./$SECRETS_DIR/oidc
mkdir -p ./$SECRETS_DIR/ssl
mkdir -p ./$SECRETS_DIR/clients
mkdir -p ./$SECRETS_DIR/jwks-certs
mkdir -p ./tests/resources/secrets

###
# Create ca for local selfsigned certificates
###
if [[ ! -f $SECRETS_DIR/cacert.crt ]]; then
  openssl genrsa -out $SECRETS_DIR/cacert.key 4096
  openssl req -x509 -new -nodes -sha256 -days 1024 \
	  -key $SECRETS_DIR/cacert.key \
	  -out $SECRETS_DIR/cacert.crt \
	  -subj "/C=US/CN=inge-6-uzipoc-ca"
fi

###
# SSL certs
###
if [[ ! -f $SECRETS_DIR/ssl/server.crt ]]; then
  create_key_pair $SECRETS_DIR/ssl "server" "localhost"
fi

###
# JWE signing cert
###
if [[ ! -f $SECRETS_DIR/nl-rdo-max-private.crt ]]; then
  create_key_pair $SECRETS_DIR "nl-rdo-max-private" "nl-rdo-max-private"
  cp $SECRETS_DIR/nl-rdo-max-private.crt $SECRETS_DIR/jwks-certs/
fi

###
# OIDC JWT signing
###
if [[ ! -f $SECRETS_DIR/oidc/selfsigned.crt ]]; then
  create_key_pair $SECRETS_DIR/oidc "selfsigned" "oidc_sign"
  cp $SECRETS_DIR/oidc/selfsigned.crt $SECRETS_DIR/jwks-certs/
fi

###
# userinfo JWT signing
###
if [[ ! -f $SECRETS_DIR/userinfo/jwe_sign.crt ]]; then
  create_key_pair $SECRETS_DIR/userinfo "jwe_sign" "max-jwe"
  cp $SECRETS_DIR/userinfo/jwe_sign.crt $SECRETS_DIR/jwks-certs/
fi

###
# Local client certificate generation
###
if [[ ! -f $SECRETS_DIR/clients/test_client/test_client.pub ]]; then
  mkdir -p $SECRETS_DIR/clients/test_client
  create_key_pair $SECRETS_DIR/clients/test_client "test_client" "max-test-client"
fi

###
# saml tvs
###
if [[ ! -f $SAML_DIR/tvs/certs/sp.crt ]]; then
  mkdir -p $SAML_DIR/tvs/certs
  create_key_pair $SAML_DIR/tvs/certs "sp" "tvs-sp"
fi

###
# saml tvs tls
###
if [[ ! -f $SAML_DIR/tvs/certs/tls.crt ]]; then
  mkdir -p $SAML_DIR/tvs/certs
  create_key_pair $SAML_DIR/tvs/certs "tls" "max-tvs"
fi

###
# saml tvs dv-cluster-cert
###
if [[ ! -f $SAML_DIR/tvs/certs/dv.crt ]]; then
  mkdir -p $SAML_DIR/tvs/certs
  create_key_pair $SAML_DIR/tvs/certs "dv" "dv"
fi

###
# max tls
###
if [[ ! -f $SECRETS_DIR/tls.crt ]]; then
  create_key_pair $SECRETS_DIR "tls" "max-tls"
fi
###
# cibg client certs
###
if [[ ! -f $SECRETS_DIR/userinfo/cibg-client-cert.crt ]]; then
  create_key_pair $SECRETS_DIR/userinfo "cibg-client-cert" "cibg-client-cert"
fi

#####
# Test certificates
#####
###
# test tls
###
if [[ ! -f tests/resources/secrets/tls.crt ]]; then
  create_key_pair tests/resources/secrets "tls" "test-tls"
fi
###
# test sp
###
if [[ ! -f tests/resources/secrets/sp.crt ]]; then
  create_key_pair tests/resources/secrets "sp" "test-sp"
fi
###
# test cluster
###
if [[ ! -f tests/resources/secrets/cluster.crt ]]; then
  create_key_pair tests/resources/secrets "cluster" "test-cluster"
fi
