# Argon Server

Server for the Argon authentication API. Written in Rust.

If you are simply looking to use Argon in your mod, more information on doing that can be found on the [Argon](https://github.com/GlobedGD/argon) repository. This repository only contains the documentation for the [Server API](./docs/server-api.md) (that you'll also need) and the [Client API](./docs/client-api.md) (that you will not need unless you want to make your own Argon client).

## Building the server

```bash
rustup override set nightly
cargo build # or cargo build --release
```

## Config & run (central)

Running the executable will cause a `Rocket.toml` and `config.json` files to be generated in the current working directory, there you can adjust various settings.

Accounts should be added like so:

```json
"accounts": [
    {
        "id": 29843187,
        "gjp": "your gjp"
    }
]
```

## Config & run (node)

Run the exectuable like so: `argon-node.exe <server> <password>` where `<server>` is the address and port of the node handler and password is the password. Both of those come from central's `config.json`, and the central server you are specifying must have `distributed_mode` set to `true`.
