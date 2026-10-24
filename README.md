# Argon Server

Server for the Argon authentication API. Written in Rust.

If you are simply looking to use Argon in your mod, more information on doing that can be found on the [Argon](https://github.com/GlobedGD/argon) repository. This repository only contains the documentation for the [Server API](./docs/server-api.md) (that you'll also need) and the [Client API](./docs/client-api.md) (that you will not need unless you want to make your own Argon client).

## Building the server

```bash
rustup override set nightly # nightly 1.100 or later is required
cargo build # or cargo build --release
```

## Setup TLS

For communication between the central server and nodes, Argon uses QUIC, which uses TLS and requires a certificate. To set up a self-signed certificate:

```sh
mkdir certs

# CA private key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/ca.key
# CA certificate
openssl req -x509 -new -key certs/ca.key -sha256 -days 3650 -out certs/ca.crt \
  -subj "/C=US/O=Example/CN=Example Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

# Server key
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/server.key
# Create sign request
openssl req -new -key certs/server.key -out certs/server.csr -subj "/CN=argon.internal" \
  -addext "subjectAltName=DNS:argon.internal"

# Sign the request with the CA to create a certificate
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -copy_extensions copy -sha256 -days 825 -out certs/server.crt
```

You'll have the following files you need to use later (and a few other, mostly unimportant ones):
* `certs/ca.crt` - The root CA certificate, needed for *nodes*
* `certs/server.key` - TLS key, needed for central server
* `certs/server.crt` - TLS certificate, needed for central server

## Configure & run

TODO