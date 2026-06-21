# ORT Protocol Specification (v1)

ORT is a transparent TCP-forwarding tunnel with a custom, cipher-suite-agile
post-quantum handshake. It cares nothing about the upper-layer protocol — any
TCP byte stream tunnels through unchanged.

```text
app ──tcp──▶ ortc ──[ORT over TCP]──▶ ortd ──tcp──▶ target
```

## Cipher suites

All primitives sit behind a `CipherSuite` trait; the symmetric record
primitives (AES-256-GCM, HKDF-SHA256, BLAKE3) are fixed for every suite, so an
established session is suite-independent.

| id       | KEM            | signatures | notes                       |
|----------|----------------|------------|-----------------------------|
| `0x0001` | ML-KEM-768     | ML-DSA-65  | post-quantum (unaudited)    |
| `0x0002` | DHKEM(X25519)  | Ed25519    | classical, audited primitives |

The **signature algorithm is decoupled from the KEM suite**: a client signs its
ClientHello once under a chosen `sig_alg` (its identity), independent of which
KEM suite(s) it offers.

## Key agreement (KEM + DEK wrapping)

Key agreement is a **KEM**, not a NIKE. The client generates a fresh random
session key `enc_sk` (the DEK), encrypts the early data once under it, and for
each offered suite encapsulates against that suite's server public key and wraps
a copy of `enc_sk`:

```text
enc_sk      = random 32 bytes (per connection)
(ct_i, k_i) = Suite_i.encapsulate(server_pk_i, r_i)        # r_i fresh per offer
wrap_key_i  = HKDF(k_i, salt=BLAKE3-256(ct_i), "ORT-v1 wrap-key")
wrapped_i   = AES-256-GCM(wrap_key_i, nonce=0, aad=suite_id_i, enc_sk)
enc_data    = record-seal(enc_sk-derived keys, early_data)
```

The server adopts whichever offered suite it supports, decapsulates `ct`,
unwraps `enc_sk`, and decrypts. If it shares no suite it replies `ServerReject`
(it never fails). Because `enc_sk` is random per connection, the derived record
keys are unique — no cross-session `(key, nonce)` reuse.

### Record keys & nonces

```text
ENC_KEY  = HKDF(enc_sk, salt=ConnMeta.nonce, "ORT-v1 enc-key")
POOL_KEY = HKDF(enc_sk, salt=ConnMeta.nonce, "ORT-v1 pool-key")
```

Each direction has an independent BLAKE3-keyed pool (keyed with `POOL_KEY`,
seeded with the ConnMeta nonce). A record nonce is `XOF(pool || counter)`; the
monotonic per-direction counter guarantees uniqueness and the ciphertext is
absorbed after each record. AAD = `"ORT-v1 rec" || dir || counter` binds
direction and sequence. The record layer splits into independent send/receive
halves so the two directions run lock-free in separate tasks (full duplex).

### ConnMeta and anti-replay

Each client flight carries `ConnMeta = {src_ip(16), ts_millis, nonce(32)}` and
one signature over:

```text
"ORT-v1 connmeta" || version || sig_alg || src_ip || ts || nonce
                  || client_pk || H(offers) || H(enc_data)
```

The **protocol version and the cipher-suite material are bound into the
signature** (version + sig_alg explicitly, KEM suite ids via `H(offers)`).

Server validation order (fail-fast / DoS-aware):

1. `src_ip == observed peer IP`;
2. `ts` within the window (default 2000 ms, +1000 ms skew tolerance);
3. client signature (authenticates offers + enc_data + version + sig_alg);
4. replay guard: `BLAKE3-256(nonce || enc_data)` unseen in the window;
5. select a mutually-supported offered suite (else `ServerReject`);
6. decapsulate, unwrap `enc_sk`, derive keys, open early data.

The replay guard is a lock-free structure (a sharded concurrent set for atomic
check-and-insert plus an ordered queue that self-evicts expired tags); no lock
is held across the cryptographic work.

### Handshake modes

- **1-RTT (first contact):** `ClientHelloOneRtt{client_pk, sig_alg, available_suites}`
  → `ServerHello{accepted_suite, server_pk, certificate, observed_ip, server_ts}`
  → `ClientData{..}`. The client takes its `src_ip` for ConnMeta from
  `observed_ip` (so it is correct behind NAT).
- **0-RTT (cached suites):** `ClientHelloZeroRtt{client_pk, sig_alg, payload}` with
  early data → `ServerAck{accepted_suite, ek_hash = BLAKE3-512(ENC_KEY)}`. The
  client requires a matching ServerAck (for an offered suite) before trusting
  the channel; a missing ack or a `ServerReject` tears the connection down.

### Certificate binding

The server's KEM public key is embedded in an X.509 custom extension (OID
`1.3.6.1.4.1.58271.1.1`, an unregistered placeholder PEN). Strict clients parse
the certificate, check validity and signature (self-signed or against a pinned
`--ca`), and require the embedded key to equal the ServerHello `server_pk`.
`--no-strict-cert` uses trust-on-first-use with caller-side pinning.

## Wire format

Each frame is `u32 length (BE) || body`, `body = u8 type || fields`. Variable
fields use a `u32` length prefix; fixed fields (hashes, IPs, nonces) are fixed
arrays validated structurally; the `DataRecord` direction is a validated boolean.
The length prefix is bounded by `MAX_FRAME`. (An explicit binary codec is used
rather than FlatBuffers so the build needs no codegen toolchain and the parser
is trivial to fuzz.)

## Security caveats

1. **0-RTT replay** is closed by the 2 s signed-timestamp window + source-IP
   binding + the `BLAKE3-256(nonce||enc_data)` strike guard. Residual: the guard
   is per-instance (no cross-instance dedup); source-IP binding is coarse behind
   NAT (which falls back to 1-RTT).
2. **Forward secrecy** is bounded by the server's long-term KEM key: an attacker
   who records `ct` and later compromises the server KEM secret can recover that
   session's `enc_sk`. Sessions are independent (fresh `enc_sk`); rotate keys to
   bound exposure. (Treated as acceptable since the server key/cert is secret.)
3. **Un-audited PQ crates.** `ml-kem`/`ml-dsa` are pre-1.0 and unaudited; the v2
   suite (X25519/Ed25519) uses audited primitives for deployments that prefer
   them.
4. **Unrestricted client identity.** The server accepts any `client_pk`; the
   signature only authenticates the current handshake (transport layer is not an
   authn layer). Layer a client allow-list on top if needed.
5. **TOFU caveat.** `--no-strict-cert` trusts `server_pk` on first contact;
   prefer strict mode (cert-bound key) on untrusted networks.
6. **Key hygiene.** Long-term key seeds are `Zeroizing`; live X25519/Ed25519 keys
   zeroize on drop (dalek). The entropy pool uses BLAKE3 with the `zeroize`
   feature. RNG failure on the per-connection path returns an error (the
   connection is rejected) rather than panicking.
