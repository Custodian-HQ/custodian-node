# custodian-node

Node SDK for Custodian Data Vault. No runtime dependencies: it uses Node's own crypto.

**Needs Node 24.15 or later** (`engines`, `.nvmrc`). Earlier Node versions lack ML-KEM, so the hybrid disclosure suite is
not available on them. The classic X25519 suite (`SUITE_CLASSIC`) still works on Node 22, but this package asks for 24.15
to keep one tested configuration.

## Check everything

    nvm use          # Node 24
    npm ci
    npm run check

Runs the type check, lint, the tests, and the build. CI runs exactly this.

## What is here

| Path | Contents |
|---|---|
| `src/custodian.ts` | `Custodian`: a method for every operation of the business API (customers, sessions, templates, webhook endpoints and deliveries, recovery policy, usage, audit events) |
| `src/webhook.ts` | `verify` and `constructEvent` for the `Custodian-Signature` header, tested against the shared known answers, including a signature the API's own code made |
| `test/spec/` | The API spec, vendored and pinned. A test fails if the SDK calls an operation the spec lacks, or the spec has one the SDK lacks |
| `src/client.ts` | HTTP client: API key, idempotency keys on POST, typed `APIError`. No endpoint methods yet: they arrive with the API in Phase 1. |
| `src/return.ts` | `parseReturn`: reads the address the customer comes back to. It trusts only the session id, and only with your own `state`. |
| `src/disclosure.ts` | Disclosure keys and opening (receiver side). Key commitment compared in constant time before decrypting. |
| `src/hpke.ts` | HPKE (RFC 9180) receiver on `node:crypto` only: X25519 and X-Wing (`draft-ietf-hpke-pq`) |
| `test/fixtures/v1/` | Fixtures vendored from `custodian-device-crypto`, checked against its manifest and a pinned hash |

The HPKE code is receiver-side only and has been checked against the published X-Wing vector and a message sealed by the
Go implementation. It is in scope for the independent audit (SEC-05).

## Taking a new API spec

    node scripts/vendor-spec.mjs ../../go/Custodian

Review the diff. Add the SDK method for any new operation: the drift test fails until you do.

## Taking new fixtures

    node scripts/vendor-fixtures.mjs ../../go/custodian-device-crypto

Review the diff. The tests fail if any fixture differs from the manifest, or the manifest from `test/fixtures.lock`.

## Licence

MIT. See `LICENSE`.

## Check who signed a disclosure

Every approved disclosure is signed by the customer's vault-sign key. Check it against the key you kept from the `customer.enrolled` webhook, never against a key you fetch when you open the envelope.

```ts
const store = new MemoryKeyStore(); // use your own database in production

// In your webhook handler, for every event after constructEvent:
await observe(store, event); // throws KeyStoreError 'key_changed': treat as an attack

// When you fetch an envelope:
const opened = await openEnvelopeFor(store, envelope, { requestId, businessId, customerId, kid, keys, suite, privateKey });
```

`openEnvelopeFor` throws `no_key` if you hold no key for the customer. A key changes only after `customer.reset` or `customer.deleted`.
