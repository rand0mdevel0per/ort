# ORT Protocol Specification (v1)

ORT is a transparent TCP-forwarding tunnel with a custom post-quantum handshake.
It cares nothing about the upper-layer protocol — any TCP byte stream (HTTP,
SSH, telnet, …) tunnels through unchanged.

- `ortc` (client) listens locally and tunnels each accepted TCP connection to a
  remote `ortd` over the ORT protocol.
- `ortd` (server) terminates the tunnel and forwards the decrypted plaintext to
  a fixed backend target.

```
app ──tcp──▶ ortc ──[ORT over TCP]──▶ ortd ──tcp──▶ target
```

## Cryptographic design

Key agreement is a **KEM** (ML-KEM-768), not a NIKE. The server holds a static
ML-KEM keypair `(dk, ek = ServerPK)`. The client, holding a verified `ServerPK`,
picks a fresh 32-byte seed `r` and runs deterministic encapsulation
`encapsulate(ek, r) → (ciphertext, k_sk)` locally, derives keys, encrypts its
first data, and sends `ciphertext`. The server recovers `k_sk` by decapsulating
`ciphertext` with `dk`. Because `r` is fresh per connection, every session has
an independent shared secret — there is no cross-session key/nonce reuse.

v1 cipher suite (`0x0001`): **ML-KEM-768 + ML-DSA-65 + AES-256-GCM +
HKDF-SHA256 + BLAKE3-512**. All primitives sit behind a `CipherSuite` trait so a
future suite (e.g. a classical DHKEM-X25519 + Ed25519 suite) can be added.

### Key schedule

```
k_sk     = decapsulate(dk, ciphertext)          # == encapsulate(ek, r).shared
salt     = BLAKE3-256(ciphertext)
ENC_KEY  = HKDF-SHA256(ikm=k_sk, salt, info="ORT-v1 enc-key",  32)
POOL_KEY = HKDF-SHA256(ikm=k_sk, salt, info="ORT-v1 pool-key", 32)
```

### Record layer & nonces

Both peers maintain a per-session BLAKE3-keyed entropy pool (keyed with
`POOL_KEY`, seeded with the ConnMeta nonce), with one independent sub-pool per
direction. A record nonce is `XOF(pool_state || counter)`; the monotonic
per-direction counter guarantees in-session uniqueness, and after each record
the ciphertext is absorbed back so subsequent nonces are unpredictable while
staying identical on both peers. The AEAD AAD is
`"ORT-v1 rec" || dir || counter_be`, binding direction and sequence.

### ConnMeta and anti-replay

Each client flight carries `ConnMeta = { src_ip(16), ts_millis(u64), nonce(32) }`
and an ML-DSA signature over:

```
"ORT-v1 connmeta" || src_ip || ts_be || nonce
                  || client_pk || BLAKE3-256(ciphertext) || BLAKE3-256(enc_data)
```

The server validates, in order (fail-fast, DoS-resistant):

1. source IP equals the observed peer IP;
2. timestamp within the acceptance window (default 2000 ms, +1000 ms skew);
3. client signature (authenticates ConnMeta + ciphertext + enc_data);
4. replay strike cache: `BLAKE3-256(nonce || enc_data)` not seen within the
   window (entries older than the window are evicted);
5. decapsulate, derive keys, open early data.

### Handshake modes

- **1-RTT (first contact):** `ClientHelloOneRtt{suite, client_pk}` →
  `ServerHello{suite, server_pk, certificate, server_ts}` → client verifies the
  certificate and `ServerPK`, then sends `ClientData{client_pk, payload}`.
- **0-RTT (cached `ServerPK`):** `ClientHelloZeroRtt{suite, client_pk, payload}`
  with early data → server replies `ServerAck{ek_hash = BLAKE3-512(ENC_KEY)}` for
  key confirmation. After the first connection, all subsequent ones are 0-RTT.

### Certificate binding

The server's ML-KEM `ServerPK` is embedded in an X.509 custom extension
(OID `1.3.6.1.4.1.58271.1.1` — an **unregistered placeholder PEN**). Strict
clients parse the certificate, check validity, verify the signature (self-signed
or against a pinned CA), and require the embedded key to equal the ServerHello
`ServerPK`, closing the MITM key-substitution gap. `--no-strict-cert` instead
uses trust-on-first-use with caller-side pinning.

## Wire format

Each frame is `u32 length (BE) || body`, with `body = u8 type || fields`.
Variable fields are length-prefixed (`u16` for handshake blobs, `u32` for record
payloads). Frame types: `ClientHelloOneRtt(0x01)`, `ClientHelloZeroRtt(0x02)`,
`ClientData(0x03)`, `ServerHello(0x04)`, `ServerAck(0x05)`, `DataRecord(0x06)`,
`Close(0x07)`. (An explicit binary codec is used rather than FlatBuffers so the
build needs no external codegen toolchain and the parser is trivial to fuzz.)

## Security caveats (read before production use)

1. **0-RTT replay** is closed by the combination of the 2 s signed-timestamp
   window, source-IP binding, and the `BLAKE3-256(nonce || enc_data)` strike
   cache. Residual considerations: the strike cache is the server's only mutable
   state and must be bounded against flooding; multiple `ortd` instances do not
   share the cache (use shared storage if strict global dedup is required);
   source-IP binding is coarse behind NAT.
2. **Forward secrecy is limited.** The server ML-KEM key is long-term. Although
   each session uses a fresh `k_sk`, an attacker who records `ciphertext` and
   later compromises `dk` can recover that session's `ENC_KEY`. Sessions are
   mutually independent (one compromise does not cascade), and there is no nonce
   reuse. Rotate the server KEM key to bound exposure; an ephemeral-KEM hybrid
   would restore full FS.
3. **Un-audited PQ crates.** `ml-kem` and `ml-dsa` (RustCrypto) are pre-1.0 and
   have not been independently audited (`ml-dsa` had advisory
   GHSA-5x2r-hc65-25f9). Use at your own risk.
4. **Unrestricted client identity.** The server accepts any `ClientPK`; the
   client signature only authenticates the current handshake, not an authorized
   identity. Layer a `ClientPK` allow-list on top if client authentication is
   required.
5. **TOFU caveat.** `--no-strict-cert` trusts `ServerPK` on first contact; an
   active MITM present at first contact is undetectable until a later pin
   mismatch. Prefer strict mode on untrusted networks.
6. **Certificate trust anchoring.** Strict mode verifies the certificate's
   signature (self-signed, or against a single pinned `--ca`) and the ServerPK
   binding; full multi-level X.509 chain validation against a system trust store
   is not yet implemented.
7. **Key hygiene.** Long-term key *seeds* are wrapped in `Zeroizing` at the CLI
   layer; the live PQ key objects are not yet zeroized (upstream crates need
   their `zeroize` feature) — tracked as a hardening item.
