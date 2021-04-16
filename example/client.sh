#!/bin/bash

openssl s_client -dtls -CAfile server-ca.crt.pem -cert client.crt.pem -key client.key.pem -connect localhost:9000
