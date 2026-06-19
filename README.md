# ort

A post-quantum secure, 0-RTT/1-RTT transparent transport protocol with
protocol-level replay protection. **ML-KEM-768 + ML-DSA-65**, source-IP-bound
signed ConnMeta, near-stateless server (only a 2 s replay strike cache),
care-nothing upper layer (HTTP / telnet / any TCP protocol).

See [SPEC.md](./SPEC.md) for the protocol and security model.

## Build

```sh
cargo build --release
```

Produces `ortd` (server) and `ortc` (client).

## Quick start (trust-on-first-use)

```sh
# server: forward decrypted traffic to a local backend on :80
ortd --listen 0.0.0.0:436 --target 127.0.0.1:80

# client: expose a local port that tunnels to the server
ortc --listen 127.0.0.1:8135 --target SERVER_IP:436 --no-strict-cert
```

Traffic to `127.0.0.1:8135` is tunnelled to `ortd` and emerges at `127.0.0.1:80`.
The first connection uses 1-RTT; subsequent ones use 0-RTT.

## With a certificate (strict verification)

```sh
# generate a server key + self-signed cert that binds the ML-KEM public key
ortd gen-cert --out ./cert

# run the server with that key/cert directory
ortd --listen 0.0.0.0:436 --target 127.0.0.1:80 --cert ./cert

# client verifies the cert's ServerPK binding (omit --no-strict-cert)
ortc --listen 127.0.0.1:8135 --target SERVER_IP:436
#   add --ca ca.der to anchor to a CA instead of self-signed
```

## Workspace layout

| crate       | role                                                            |
|-------------|-----------------------------------------------------------------|
| `ort-core`  | sans-IO protocol brain: cipher suite, key schedule, handshake   |
| `ort-proto` | wire format: frame types + length-prefixed binary codec         |
| `ort-net`   | tokio transport, session driver, forwarding, cert verification  |
| `ort-cli`   | shared CLI plumbing (logging, key IO)                           |
| `ortc`      | client binary                                                   |
| `ortd`      | server binary (`run`, `gen-key`, `gen-cert`)                    |

## Test

```sh
cargo test --workspace
```
