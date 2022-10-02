#! /bin/bash

NAME=$1
DOMAIN=showcert

# Create root CA & Private key
openssl req -x509 \
            -sha256 -days 356 \
            -nodes \
            -newkey rsa:2048 \
            -subj "/CN=${DOMAIN}/C=US/L=Minneapolis" \
            -keyout tmp/rootCA.key -out tmp/rootCA.crt

# Create csf conf
cat > tmp/csr.conf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Minnesota
L = Minneapolis
O = ShowCert
OU = ShowCert Root
CN = ${DOMAIN}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${DOMAIN}
DNS.2 = www.${DOMAIN}
IP.1 = 192.168.1.5
IP.2 = 192.168.1.6

EOF

# Create a external config file for the certificate
cat > tmp/cert.conf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}

EOF

## Create keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:3 -out tmp/rsa_2048_exp3.key
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_keygen_pubexp:9 -out tmp/rsa_4096_exp9.key
#
## To check curves available on system: openssl ecparam -list_curves
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -pkeyopt ec_param_enc:named_curve -out tmp/ecdsa.key
openssl genpkey -algorithm ED25519 -out tmp/ed25519.key

# Create SSl with self signed CA
create_cert() {
  # create CSR request using private key
  openssl req -new -key tmp/"${1}.key" -out tmp/"${1}.csr" -config tmp/csr.conf

  # Create Cert
  openssl x509 -req \
      -in tmp/"${1}.csr" \
      -CA tmp/rootCA.crt -CAkey tmp/rootCA.key \
      -CAcreateserial -out test_data/"${1}.crt" \
      -days 365 \
      -sha256 -extfile tmp/cert.conf
}

create_cert rsa_2048_exp3
create_cert rsa_4096_exp9
create_cert ecdsa
create_cert ed25519
