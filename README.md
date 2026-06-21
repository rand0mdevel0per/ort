# ort

A post-quantum, cipher-suite-agile, 0-RTT/1-RTT transparent transport protocol
with protocol-level replay protection. Two suites — **PQC: ML-KEM-768 + ML-DSA-65**
(post-quantum) and **ECDH: DHKEM(X25519) + Ed25519** (audited classical) — are
negotiable, with the signature identity decoupled from the KEM suite. Source-IP
bound signed ConnMeta, a lock-free 2 s replay strike guard, care-nothing upper
layer (HTTP / telnet / any TCP protocol).

See [SPEC.md](./SPEC.md) for the protocol and security model.

## Build

```sh
cargo build --release
```

Produces `ortd` (server) and `ortc` (client).

## Quick start (trust-on-first-use)

```sh
# server: forward decrypted traffic to a local backend on :80
ortd run --listen 0.0.0.0:436 --target 127.0.0.1:80

# client: expose a local port that tunnels to the server
ortc --listen 127.0.0.1:8135 --target SERVER_IP:436 --no-strict-cert
```

Traffic to `127.0.0.1:8135` is tunnelled to `ortd` and emerges at `127.0.0.1:80`.
The first connection uses 1-RTT; subsequent ones use 0-RTT. By default the client
offers both suites (`--suites pqc,ecdh`) and signs with ML-DSA (`--sig-alg pqc`);
the server adopts whichever offered suite it holds a key for, or replies `ServerReject`.

## With a certificate (strict verification)

```sh
# generate per-suite server key(s) + self-signed cert(s) binding the public key(s)
ortd gen-cert --out ./cert            # --suite all (default) | pqc | ecdh

# run the server with that key/cert directory
ortd run --listen 0.0.0.0:436 --target 127.0.0.1:80 --cert ./cert

# client verifies the cert's server-key binding (omit --no-strict-cert)
ortc --listen 127.0.0.1:8135 --target SERVER_IP:436
#   --ca ca.der    anchor to a CA instead of self-signed
#   --suites ecdh --sig-alg ecdh   use the classical suite only
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

## Friendly links

* [LINUX DO](https://linux.do) I learnt a lot in it! (Notice: This forum is entirely in Simplified Chinese.)
