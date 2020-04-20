# PKI Instructions

## Mock Federated SSO Certificate

For testing purposes, we need to create a mock SAML assertion validation
certificate and associated private key.

First, create `assets/idp/azure_ad_app_signing_openssl.conf`:

```
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
basicConstraints=CA:FALSE
nsCertType = client, server, email
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth, codeSigning, emailProtection
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName = @alt_names

[alt_names]
DNS.0 = localhost
IP.0 = 127.0.0.1

[v3_ext]
```

Next, generate a federated SSO certificate:

```bash
openssl req -x509 -sha256 -nodes \
  -config assets/idp/azure_ad_app_signing_openssl.conf \
  -subj "/CN=Microsoft Azure Federated SSO Certificate" \
  -days 1095 -newkey rsa:2048 \
  -keyout assets/idp/azure_ad_app_signing_key.pem \
  -out assets/idp/azure_ad_app_signing_cert.pem \
  -extensions v3_ext
```

By replacing `-extensions v3_ext` with `-extensions v3_req` in the above
command, the following X509v3 extensions extensions would be added:

```
        X509v3 extensions:
            X509v3 Basic Constraints:
                CA:FALSE
            Netscape Cert Type:
                SSL Client, SSL Server, S/MIME
            X509v3 Key Usage:
                Digital Signature, Non Repudiation, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication, Code Signing, E-mail Protection
            X509v3 Subject Key Identifier:
                50:15:0F:E2:4C:1B:E0:1A:D5:58:C5:5F:69:66:84:22:2A:1B:F9:9B
            X509v3 Authority Key Identifier:
                keyid:50:15:0F:E2:4C:1B:E0:1A:D5:58:C5:5F:69:66:84:22:2A:1B:F9:9B
```

As the result of the above command, the `assets/idp/azure_ad_app_signing_cert.pem`
contains mock "Microsoft Azure Federated SSO Certificate":

```
$ openssl x509 -noout -text -in assets/idp/azure_ad_app_signing_cert.pem
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ... omitted ...
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Microsoft Azure Federated SSO Certificate
        Validity
            Not Before: Feb 26 03:24:24 2020 GMT
            Not After : Feb 26 03:24:24 2023 GMT
        Subject: CN=Microsoft Azure Federated SSO Certificate
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    ... omitted ...
                Exponent: 65537 (0x10001)
    Signature Algorithm: sha256WithRSAEncryption
         ... omitted ...
```
