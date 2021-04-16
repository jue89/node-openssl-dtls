#!/bin/bash


PKINAME="$1"
if [ -z "$PKINAME" ]; then
    echo "Usage: $0 [pkiname]" >&2
    exit 1
fi

openssl ecparam -name "prime256v1" -out "prime256v1.pem"

# CA CRT + KEY
openssl ecparam -in "prime256v1.pem" -genkey -noout -out "$PKINAME-ca.key.pem"
openssl req -new -sha256 -key "$PKINAME-ca.key.pem" -out "$PKINAME-ca.csr.pem" -subj "/CN=$PKINAME"
openssl x509 -req -sha256 -days 18262 -in "$PKINAME-ca.csr.pem" -extfile "openssl.cnf" -extensions "v3_ca" -signkey "$PKINAME-ca.key.pem" -out "$PKINAME-ca.crt.pem" -set_serial "$(date +%s)"

# Child CRT + KEY
openssl ecparam -in "prime256v1.pem" -genkey -noout -out "$PKINAME.key.pem"
openssl req -new -sha256 -key "$PKINAME.key.pem" -out "$PKINAME.csr.pem" -subj "/CN=$PKINAME Child"
openssl x509 -req -sha256 -days 18262 -in "$PKINAME.csr.pem" -extfile "openssl.cnf" -extensions "v3_device" -CA "$PKINAME-ca.crt.pem" -CAkey "$PKINAME-ca.key.pem" -out "$PKINAME.crt.pem" -set_serial "$(date +%s)"

