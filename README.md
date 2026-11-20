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
10. [Read your usage and audit log](#10-read-your-usage-and-audit-log)

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

A call waits up to 30 seconds for the vault to answer. Change this with `timeoutMs`; `0` turns the limit off. When the limit is
reached, the call throws an error with `error.name === 'TimeoutError'`. For a file download the limit applies to the wait for the
answer to start, not to the time it takes to read the file.

```ts
const custodian = new Custodian(process.env.CUSTODIAN_API_KEY!, { timeoutMs: 10_000 });
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
- If you repeat a call with the same `idempotencyKey`, the answer has `secret_not_replayable: true` and no `url`. Make a new session
  with a new key to get a new link.

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
import { MemoryKeyStore, constructEvent, observeEvent, KeyStoreError } from '@custodian-hq/vault-node';

const store = new MemoryKeyStore(); // in production, keep keys in your own database

const app = express();

app.post('/webhooks/custodian', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const event = constructEvent(process.env.CUSTODIAN_WEBHOOK_SECRET!, req.header('Custodian-Signature') ?? '', req.body);
    // The same event can arrive more than once: ignore an event.id you already handled.

    try {
      // Keeps the customer's signing key from "customer.enrolled".
      await observeEvent(store, event, {
        // Say yes only if you started this reset or confirmed it with your own customer.
        approveReset: (customerId) => resetIsExpected(customerId),
      });
    } catch (error) {
      if (!(error instanceof KeyStoreError && error.code === 'stale_event')) throw error; // stale_event: an old event came late; acknowledge it
    }

    // Handle event.type here.
    res.sendStatus(200);
  } catch {
    res.sendStatus(400); // the signature is wrong or too old
  }
});
```

**Why `observeEvent` matters.** When a customer enrols, the event holds their **signing key**. Keep it.
Later you use it to prove that data really came from this customer.
If a later event names a different key, `observeEvent` throws a `KeyStoreError` with the code `key_changed`. Do not trust the new key. Find out why it changed before you go on.

Webhooks are signed by Custodian with a secret that Custodian also holds. So a valid signature does not prove that a `customer.reset` is real.
That is why a reset erases the key only when your `approveReset` callback says yes. Without the callback, `observeEvent` refuses every reset
(`reset_not_approved`) and keeps the key. Approve a reset only when you started it or confirmed it with your own customer.
Every `KeyStore` has `advanceLastEvent(customerId, created)`. `observeEvent` calls it first. It must be one atomic step: keep the newer of the stored
time and `created`, and return `false` if `created` is older. An event older than one already handled throws `stale_event` and does nothing else: a
retried old event cannot pin an old key or erase a new one. The older `observe` function trusts the vault: it asks for no approval and does not check
the order of events.

**Breaking change.** `KeyStore` has a new required method, `advanceLastEvent`. It replaces the optional `lastEvent` and `setLastEvent`, which are
removed. If you have your own store, add the method (see the docs page "Key store"). `MemoryKeyStore` has it.

## 6. Other things a customer can do

You start every visit the same way as in step 3. Only the purpose changes.

| Purpose | Use it to |
|---|---|
| `Purpose.Enrol` | Let a new customer create their vault |
| `Purpose.Entry` | Let the customer add data. Give a `template` or `keys`. |
| `Purpose.View` | Let the customer see a record. Give the `record` token. |
| `Purpose.Approve` | Let the customer approve a disclosure request. Give the `disclosure` id. See step 7. |
| `Purpose.RecoverySettings` | Let the customer change their secret (new secret and new master key) |
| `Purpose.Reset` | Start a reset. Use `customers.reset`. |
| `Purpose.Delete` | Let the customer delete their own data |

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
| `key_changed` | An event names a different key than the one you kept. Do not trust the new key. Find out why it changed before you go on. |
| `reset_not_approved` | A `customer.reset` or `customer.deleted` event did not erase the key, because `approveReset` is not set or said no. |
| `stale_event` | The event is older than one already handled for this customer. Nothing changed. Acknowledge it. |
| `signature` | The customer's key did not sign this envelope, or the envelope was sealed to a key that is not your disclosure key. |
| `request`, `business`, `customer`, `key` | The envelope is for something else than you asked. |
| `format`, `payload` | The envelope is damaged, or its content is not what the customer approved. |

### Receive a file

A file key, such as `passport`, is asked for like a value: put its name in `keys` when you create the request. To open the envelope,
give the value names in `keys` and the file names in `files`. The envelope then holds one grant for each file: the file id and its key.
The vault keeps the encrypted file. You download it and the library opens it as a stream, so a large file never sits in memory.

```ts
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { openEnvelopeFor, receiveFile } from '@custodian-hq/vault-node';

const opened = await openEnvelopeFor(store, envelope, { ...expected, keys: ['full_name'], files: ['passport'] });

// The library does not limit how many bytes a file gives. Stop the copy at a size you choose.
const MAX_BYTES = 20 * 1024 * 1024;
let written = 0;
const limit = new Transform({
  transform(chunk: Buffer, _encoding, done) {
    written += chunk.length;
    done(written > MAX_BYTES ? new Error('the file is larger than we allow') : null, chunk);
  },
});

// Download before you acknowledge: the download works only while the envelope exists (at most 15 minutes).
const tempPath = path.join(os.tmpdir(), `passport-${randomUUID()}`);
const passport = await receiveFile(custodian, opened, 'passport');
try {
  await pipeline(Readable.fromWeb(passport), limit, fs.createWriteStream(tempPath));
} catch (error) {
  await fs.promises.rm(tempPath, { force: true });
  throw error;
}
await custodian.disclosures.acknowledge(request.id);
```

- **Discard the key when you are done.** The key opens this one file only, and the customer cannot take it back. `receiveFile` clears
  the key and removes it from `opened.files` when the stream ends. If you use `downloadFile` and `openFile` yourself, clear `grant.key`
  with `grant.key.fill(0)`.
- **Use the file only if the stream ends without an error.** A `FileError` means the file was changed or cut. Delete what you wrote.
- **Limit the size you write.** A file can be compressed, and the library does not limit the total size after it is unpacked. A small
  file from a customer can become very large. Count the bytes as in the example and stop when you reach your limit.
- **Check the file type again.** The customer chose the file. Do not trust its name or its first bytes until you check them yourself.
- `410 file_replaced`: the customer replaced or removed the file after approving. Ask again. `429 busy`: try again in a moment; the
  key is kept when the download is refused before it starts.

| `FileError` code | What it means |
|---|---|
| `commitment` | The file was not made with this key. |
| `open`, `truncated` | A chunk was changed, moved, added or removed, or the file is for another key name or record. |
| `format`, `records`, `frame`, `too_long` | The file is damaged or was built to attack the reader. |
| `key_cleared` | The key of the grant was already cleared (set to zeros), so it cannot open a file. |

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

Some errors come from the library, not from the API. They are an `APIError` too:

| `code` | What it means |
|---|---|
| `unparsed_response` | The vault answered with a success status, but the body is not JSON. Look for a proxy between you and the vault. |
| `response_too_large` | An answer was larger than 32 MiB. |
| `unexpected_status` | A download got a success status that is not the one for the request: `200` for a whole file, `206` for a range. |
| `no_body` | A download answered with the right status but no body. |

A call that waited too long throws an error with `error.name === 'TimeoutError'`. A call that you stopped with your own `signal`
throws the error of that signal (`AbortError`, unless you gave another reason).

## 10. Read your usage and audit log

```ts
const usage = await custodian.usage(); // this month so far
console.log(usage.customers, usage.new_customers_7d, usage.pending_disclosures);

const events = await custodian.auditEvents({ type: 'api_key.created', actor: 'api_key', limit: 50 });
```

`usage` also takes `from` and `to` (RFC 3339 times). `auditEvents` takes these filters. All are optional.

| Filter | Meaning |
|---|---|
| `limit` | 1 to 100. The default is 20. |
| `starting_after` | The id of the last event you received. |
| `type` | One event type, such as `api_key.created`. |
| `actor` | `member` or `api_key`. |
| `from`, `to` | Events at or after `from`, and before `to`. RFC 3339 times. |
| `q` | Matches a member's email, a key id, or text in the event. Up to 100 characters. |

The list calls give you the array of items. They do not give the page fields the API also sends: the `total` of the audit log
(how many events match in all) and `grace_hours` of `disclosureKeys.list`. Call the API yourself if you need them.

Other fields you can read:

| Answer | Fields |
|---|---|
| `webhookEndpoints.list` | `secret_last4`, `failing_deliveries`, and in lists `last_delivery_at` |
| `webhookDeliveries.list` | `max_attempts`, and `next_retry_at` while a delivery is pending or retrying |
| `sessions.create` | `secret_not_replayable` on a repeat of the call |

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
