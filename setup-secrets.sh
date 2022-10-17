#!/bin/bash

set -e

SECRETS_DIR=secrets
SAML_DIR=saml

create_key_pair () {
  openssl genrsa -out $1/$2.key 2048
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

create_pub_key () {
  openssl rsa -in $1/$2.key -pubout > $1/$2.pub
}

mkdir -p ./$SECRETS_DIR/userinfo
mkdir -p ./$SECRETS_DIR/oidc
mkdir -p ./$SECRETS_DIR/ssl
mkdir -p ./$SECRETS_DIR/clients
mkdir -p ./$SECRETS_DIR/jwks-certs

###
 # Create ca for local selfsigned certificates
###
if [[ ! -f $SECRETS_DIR/cacert.crt ]]; then
  openssl genrsa -out $SECRETS_DIR/cacert.key 4096
	openssl req -x509 -new -nodes -sha256 -days 1024 \
	  -key $SECRETS_DIR/cacert.key \
	  -out $SECRETS_DIR/cacert.crt \
	  -subj "/CN=US/CN=inge-6-uzipoc-ca"
fi

###
# OIDC JWT signing
###
if [[ ! -f $SECRETS_DIR/ssl/server.crt ]]; then
  create_key_pair $SECRETS_DIR/ssl "server" "localhost"
  create_pub_key $SECRETS_DIR/ssl "server"
  cp $SECRETS_DIR/userinfo/jwe_sign.crt $SECRETS_DIR/jwks-certs
fi

###
# OIDC JWT signing
###
if [[ ! -f $SECRETS_DIR/userinfo/jwe_sign.crt ]]; then
  create_key_pair $SECRETS_DIR/userinfo "jwe_sign" "max-jwe"
  create_pub_key $SECRETS_DIR/userinfo "jwe_sign"
  cp $SECRETS_DIR/userinfo/jwe_sign.crt $SECRETS_DIR/jwks-certs
fi

###
# Local client certificate generation
###
if [[ ! -f $SECRETS_DIR/clients/test_client/test_client.pub ]]; then
  mkdir -p $SECRETS_DIR/clients/test_client
  create_key_pair $SECRETS_DIR/clients/test_client "test_client" "max-test-client"
  create_pub_key $SECRETS_DIR/clients/test_client "test_client"
fi