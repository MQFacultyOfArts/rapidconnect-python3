#!/bin/bash

pip3 install PyJWT sanic

# https://letsencrypt.org/docs/certificates-for-localhost/
openssl req -x509 -out ssl/localhost.crt -keyout ssl/localhost.key \
  -newkey rsa:2048 -nodes -sha256 \
  -subj '/CN=localhost' -extensions EXT -config <( \
   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")

sudo cp ssl/localhost.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
     