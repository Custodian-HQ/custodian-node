# Custodian Data Vault: Node SDK

Custodian Data Vault lets your business keep sensitive data for your customers, so that **only the customer holds the key**.
You see a value only when the customer approves your request for it.

This is the official Node library. Use it on your server to follow the whole journey:
make a customer, send them to the vault, hear what happened, and ask to see a value.

> **Beta.** This is version `1.0.0-beta`. The API and this library can change before `1.0.0`.
> The library version is the same as the API version it was built for.

## Before you start

- You need a Custodian account and an API key. Start with a **test** key. Test mode never touches real customer data.
- Use this library **on your server only**. Never put your API key in a browser or in a mobile app.
- You need **Node 24.15 or later**.

## The journey

1. [Install and connect](#1-install-and-connect)
2. [Create a customer](#2-create-a-customer)
3. [Send the customer to the vault](#3-send-the-customer-to-the-vault)
4. [Welcome the customer back](#4-welcome-the-customer-back)
5. [Listen for webhooks](#5-listen-for-webhooks)
6. [Other things a customer can do](#6-other-things-a-customer-can-do)
7. [Ask to see a value](#7-ask-to-see-a-value)
8. [Open the values](#8-open-the-values)
9. [Handle errors](#9-handle-errors)

Words used in this guide:

| Word | Meaning |
|---|---|
| Customer | A person whose data is in your vault. You identify them with your own user id. |
| Session | One visit of a customer to the Custodian vault page. Your server makes it. |
| Purpose | What a session is for, for example `Purpose.Enrol`. |
| Disclosure | A request to see some of a customer's values. The customer decides. |

## 1. Install and connect

```sh
npm install @custodian-hq/vault-node@beta
```

The `@beta` part is needed because this version is a pre-release.

Make one client for your whole app. Read the key from the environment.

```ts
import { Custodian } from '@custodian-hq/vault-node';

const custodian = new Custodian(process.env.CUSTODIAN_API_KEY!);

console.log(await custodian.me()); // { organization, name, livemode }
```

## 2. Create a customer

Make the customer once. Use your own id for this person.

```ts
const customer = await custodian.customers.create('user-1042');
// customer.id looks like "cus_..."
```

If you use the same id again, the API answers `customer_exists`.

## 3. Send the customer to the vault

The customer creates their key in the vault. This is a **session** with the purpose `Purpose.Enrol`.
Use the names in `Purpose` instead of writing the text by hand.

```ts
import { randomUUID } from 'node:crypto';
import { Purpose } from '@custodian-hq/vault-node';

const state = randomUUID(); // a random value. Save it for this signed-in user.
saveStateForUser(user.id, state);

const session = await custodian.sessions.create({
  customer: customer.id,
  purpose: Purpose.Enrol,
  return_url: 'https://app.example.com/vault/return',
  state,
});
// Redirect the customer to session.url
```

- The `return_url` must be one you registered in the Console.
- The `state` ties the visit to your signed-in user. Without it, an attacker could send your user to the attacker's own session.
- The link in `session.url` works one time, for 15 minutes.

## 4. Welcome the customer back

When the customer returns, do not trust the address. `parseReturn` checks it against your saved `state` and gives you the session id.
Then ask Custodian what really happened.

```ts
import { SessionStatus, parseReturn } from '@custodian-hq/vault-node';

const sessionId = parseReturn(requestUrl, loadStateForUser(user.id)); // throws if the address is not valid
const result = await custodian.sessions.retrieve(sessionId);

if (result.status === SessionStatus.Completed) {
  // The customer finished.
}
```

The `status` is one of `SessionStatus.Created`, `Exchanged`, `Completed`, `Cancelled` or `Expired`.
Always read it from `sessions.retrieve`. A customer could change the address.

## 5. Listen for webhooks

Custodian also tells your server about events with a signed request. This is the safest way to learn what happened.

Make the endpoint once, **in the Console**. Only a member can make, change, delete or rotate an endpoint, and only there.
The SDK and your API key cannot. This keeps the secret out of your code, and nobody with a stolen key can redirect your events.

1. In the Console, open **Webhooks** and choose **Add endpoint**.
2. Give your address (it must use https). Choose the events, for example `customer.enrolled` and `disclosure.approved`.
3. Confirm with your code. The Console shows the signing secret (`whsec_...`) **one time**. Store it in your secret store.

To replace a leaked secret, rotate it in the Console. The old secret stops working at once.

Then handle each request. Check the signature **before** you use anything.
Pass the raw body, not parsed JSON.

```ts
import express from 'express'; // any framework works if you pass the raw body
import { MemoryKeyStore, constructEvent, observe } from '@custodian-hq/vault-node';

const store = new MemoryKeyStore(); // in production, keep keys in your own database

const app = express();

app.post('/webhooks/custodian', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const event = constructEvent(process.env.CUSTODIAN_WEBHOOK_SECRET!, req.header('Custodian-Signature') ?? '', req.body);
    // The same event can arrive more than once: ignore an event.id you already handled.

    await observe(store, event); // keeps the customer's signing key from "customer.enrolled"

    // Handle event.type here.
    res.sendStatus(200);
  } catch {
    res.sendStatus(400); // the signature is wrong or too old
  }
});
```

**Why `observe` matters.** When a customer enrols, the event holds their **signing key**. Keep it.
Later you use it to prove that data really came from this customer.
If a later event names a different key, `observe` throws a `KeyStoreError` with the code `key_changed`. Treat that as an attack.

## 6. Other things a customer can do

You start every visit the same way as in step 3. Only the purpose changes.

| Purpose | Use it to |
|---|---|
| `Purpose.Enrol` | Let a new customer create their vault |
| `Purpose.Entry` | Let the customer add data. Give a `template` or `keys`. |
| `Purpose.View` | Let the customer see a record. Give the `record` token. |
| `Purpose.Approve` | Let the customer approve a disclosure request. Give the `disclosure` id. See step 7. |
| `Purpose.Recover`, `Purpose.RecoverySettings` | Recovery with trusted people or devices, and its settings |
| `Purpose.Reset` | Start a reset. Use `customers.reset`. |
| `Purpose.Delete` | Let the customer delete their own data |
| `Purpose.Holder` | Let the customer's second device act as a recovery holder |

`isPurpose(text)` tells you whether a text is a purpose this library knows.
A newer API can send one that the library does not know yet.

## 7. Ask to see a value

Your server cannot read stored values. To see one, you make a **disclosure** request. The customer approves it with one passkey prompt.
The values come back in a sealed envelope that only your key can open.

**One time: make your disclosure key.** Keep the private key secret. The fingerprint is not secret.

```ts
import { fingerprint, generateKey } from '@custodian-hq/vault-node';

const key = generateKey(); // keep key.privateKey in your secret store
const keyFingerprint = fingerprint(key.suite, key.publicKey); // keep this in your app config
```

Add the public key in the Console. A member of your team confirms it with a code.

**Each time you want a value:**

```ts
import { Purpose, approveUrl } from '@custodian-hq/vault-node';

// 1. Ask for named keys of one record. The request holds names, never values.
const request = await custodian.disclosures.create({
  customer: customer.id,
  record: recordToken, // the record's token, for example from custodian.records.list
  keys: ['full_name', 'date_of_birth'],
  reason: 'Identity check for your loan application',
  disclosure_key_fingerprint: keyFingerprint,
});

// 2. Start an approval visit for that request.
const approval = await custodian.sessions.create({
  customer: customer.id,
  purpose: Purpose.Approve,
  return_url: 'https://app.example.com/vault/return',
  state,
  disclosure: request.id,
});

// 3. Add your fingerprint to the link, then redirect the customer.
//    Take it from your own config, never from Custodian.
redirect(approveUrl(approval.url!, keyFingerprint));
```

The customer may also reject the request, or let it expire. The default wait is 15 minutes.

## 8. Open the values

When the customer approves, you get a `disclosure.approved` webhook. Then:

```ts
import { openEnvelopeFor } from '@custodian-hq/vault-node';

const me = await custodian.me();

// 1. Fetch the sealed envelope. You have 15 minutes.
const envelope = await custodian.disclosures.envelope(request.id);

// 2. Say what you expect to find. Open it. The library checks the customer's signature against the key you kept in step 5.
const expected = {
  requestId: request.id,
  businessId: me.organization,
  customerId: customer.id,
  kid: request.disclosure_key,
  keys: request.keys,
  suite: key.suite,
  privateKey: key.privateKey,
};
const opened = await openEnvelopeFor(store, envelope, expected);
console.log(opened.fields); // { full_name: '...', date_of_birth: '...' }

// 3. Tell Custodian you have it. The vault then deletes the envelope.
await custodian.disclosures.acknowledge(request.id);
```

If a check fails, the library throws. **Do not use the values.** Never fall back to a key that you fetched from Custodian.

```ts
import { EnvelopeError, KeyStoreError } from '@custodian-hq/vault-node';

try {
  await openEnvelopeFor(store, envelope, expected);
} catch (error) {
  if (error instanceof KeyStoreError || error instanceof EnvelopeError) {
    console.error('Do not use this envelope:', error.code);
  } else {
    throw error;
  }
}
```

| Error code | What it means |
|---|---|
| `no_key` | You hold no signing key for this customer. Check that your webhook saw `customer.enrolled`. |
| `key_changed` | An event names a different key than the one you kept. Treat it as an attack. |
| `signature` | The customer's key did not sign this envelope. |
| `request`, `business`, `customer`, `key` | The envelope is for something else than you asked. |
| `format`, `payload` | The envelope is damaged, or its content is not what the customer approved. |

## 9. Handle errors

Every failed API call throws an `APIError`.

```ts
import { APIError } from '@custodian-hq/vault-node';

try {
  await custodian.customers.create('user-1042');
} catch (error) {
  if (error instanceof APIError) {
    console.error(error.status, error.code, error.message, error.requestId);
  } else {
    throw error;
  }
}
```

Give the `requestId` to support if you need help.

## More help

- [Documentation](https://docs.thecustodian.io)
- [Quickstart](https://docs.thecustodian.io/get-started/quickstart/)
- [Sessions](https://docs.thecustodian.io/developer/sessions/)
- [Webhooks](https://docs.thecustodian.io/developer/webhooks/)
- [Disclosure](https://docs.thecustodian.io/developer/disclosure/)
- [Errors](https://docs.thecustodian.io/get-started/errors/)

## Security

To report a security problem, email **support@thecustodian.io**. Do not open a public issue for it.

## Contributing

Run `npm ci` and then `npm run check`. The check runs the type check, the lint, the tests and the build.

## Licence

MIT. See [LICENSE](LICENSE).
