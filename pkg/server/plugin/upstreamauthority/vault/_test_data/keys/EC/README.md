# Certificates and PrivateKeys for testing

## Root CA (C=US, O=SPIFFE, CN=test-root-ca)

```
openssl ecparam  -name prime256v1 -genkey -noout -out root_key.pem
openssl req -days 3650 -x509 -new -key root_key.pem -out root_cert.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://root\nbasicConstraints=CA:true") -extensions v3
```

## Intermediate CA (C=US, O=SPIFFE, CN=test-intermediate-ca)

```
openssl ecparam -name prime256v1 -genkey -noout -out intermediate_key.pem
openssl req  -new -key intermediate_key.pem -out intermediate_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://intermediate\nbasicConstraints=CA:true") -extensions v3
openssl x509 -days 3650 -req -CA root_cert.pem -CAkey root_key.pem -in intermediate_csr.pem -out intermediate_cert.pem -CAcreateserial -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://intermediate\nbasicConstraints=CA:true") -extensions v3
```

## Server Cert used by Vault (Issued by Root CA)

```
openssl ecparam -name prime256v1 -genkey -noout -out server_key.pem
openssl req  -new -key server_key.pem -out serer_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=IP:127.0.0.1") -extensions v3
openssl x509 -days 3650 -req -CA root_cert.pem -CAkey root_key.pem -in server_csr.pem -out server_cert.pem -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=IP:127.0.0.1") -extensions v3
```

## Client Cert used by Plugin (Issued by Root CA)

```
openssl ecparam -name prime256v1 -genkey -noout -out client_key.pem     
openssl req  -new -key client_key.pem -out client_csr.pem -config <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://vault-client") -extensions v3
openssl x509 -days 3650 -req -CA root_cert.pem -CAkey root_key.pem -in client_csr.pem -out client_cert.pem -extfile <(cat /etc/ssl/openssl.cnf ; printf "\n[v3]\nsubjectAltName=URI:spiffe://vault-client") -extensions v3
``
