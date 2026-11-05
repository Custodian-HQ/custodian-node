# Fixture provenance

These files are known answers for the wire format. They come from the reference implementation of that format and are copied here
unchanged, except this file. Every SDK that uses them must give the same answers.

`scripts/vendor-fixtures.mjs` copies them from a checkout of the reference implementation and pins `MANIFEST.json` in
`test/fixtures.lock`. A test checks that each file matches the manifest and that the manifest matches the pin. This file belongs to
this repository, so the script keeps it and the test checks only its name.

| File | Where it comes from |
|---|---|
| `hpke-xwing-vector.json` | One entry (KEM `0x647a` MLKEM768-X25519, KDF `0x0001`, AEAD `0x0003`) copied unchanged from `src/crypto/hpke/testdata/hpke-pq.json` in Go 1.26.0. Go's licence (BSD-3-Clause) is in `LICENSE-go.txt`. It pins the X-Wing KEM of `draft-ietf-hpke-pq`. |
| `pedersen-h.json`, `kdf.json`, `disclosure-key-fingerprint.json`, `envelope.json`, `keyring.json`, `cbor.json`, `sign.json`, `secret-normalization.json` | Made by the reference implementation. Other software checked them: Node's own `crypto` (HKDF, AES-256-GCM, Ed25519, and Argon2id on Node 24), `@noble/curves` for the ristretto255 values, Python's `hashlib` for the fingerprints, Go's `x/text` for the normalization answers, and `github.com/fxamacker/cbor` for every value of `cbor.json`. |
| `hpke-xwing-aes256gcm-sample.json`, `share-envelope.json` | Made once by the reference implementation. A seal is random, so these are not made again. Go and Node both open them. |
| `pedersen.json`, `holder-wrap.json` | Made by the reference implementation from fixed inputs. `@noble/curves` and Node's own `crypto` check them. |
| `file-stream.json`, `zstd-records.json`, `disclosure-envelope.json` | Made by the reference implementation. Each file lists inputs that must open and inputs that must be refused, with the error each one gives. |
| `webhook-signature.json` | Known answers for the `Custodian-Signature` webhook header. The first signature was made by the API's own signing code. The others follow the same rule. Every SDK must accept and refuse exactly these. |
| `MANIFEST.json` | SHA-256 of every other file here. A test fails if a hash differs. |
