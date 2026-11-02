# Argon Server

Server for the Argon authentication API. Written in Rust.

If you are simply looking to use Argon in your mod, more information on doing that can be found on the [Argon](https://github.com/GlobedGD/argon) repository. This repository only contains the documentation for the [Server API](./docs/server-api.md) (that you'll also need) and the [Client API](./docs/client-api.md) (that you will not need unless you want to make your own Argon client).

## Building the server

```bash
rustup override set nightly-2026-10-01 # later nightlies are currently broken in sea-orm
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

First, let's run the central server with a minimal configuration. Write this to `central/config.toml`:
```sh
[node_handler]
# make this secure, this is used to connect to this server
secret_key = "secret password"
# paths to the .crt and .key files we generated earlier
tls_cert = "certs/server.crt"
tls_key = "certs/server.key"

[auth]
# randomly generated 256-bit key, can be generated via `openssl rand -hex 32`
secret_key = "bf04327e3a0b61d8525a5c6dd5476fe52caaf3c77c3d8550bc95f11a1cf9ebc2"
```

After that, you can run the server, which will generate the database and start the HTTP server:
```sh
cd central
cargo run
```
If no errors are printed to the console, it worked! The server is running and the website should be accessible at http://127.0.0.1:8000

## Connect a node

The Argon backend is split into two parts: the central server (that you just ran), and the node. A single central server never makes any request to GD servers - instead it orchestrates multiple nodes which actually handle the requests. Thus, you need to run at least one node for authentication to work.

Minimal configuration for `node/config.toml`:
```toml
[central]
address = "127.0.0.1:8001"
# the ca.crt file we saved earlier
certificate = "certs/ca.crt"
# the secret_key from the [node_handler] section in the central server configuration
secret_key = "secret password"
# required when 'address' is an IP, see the Protocol section
hostname = "argon.internal"
```

Run:
```sh
cd node
cargo run
```

If everything is configured correctly and the central server is running, this should connect to it and authentication should work now.

## Protocol

The QUIC protocol is used for communication between the central server and nodes, which is secured with TLS but has multiple caveats:
* For nodes running on separate machine, they must be able to reach the **UDP** port 8001 (or whatever you specified) of the central server, aka the port must be forwarded and allowed in your firewall
* Since TLS certificates have a domain name, one must be used for connection. When `address` is set to include a domain name instead of an IP address, for example `my.server.com:8001` or `my.server.com`, no separate `hostname` needs to be specified in the config but the TLS certificate must include that domain as the common name. Otherwise, if an IP address is used, the actual hostname used does not matter but it needs to be consistent. The TLS example above uses `argon.internal` as the CN when generating the certs, so the same hostname should be used in node configuration.
