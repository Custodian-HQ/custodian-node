import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { DEFAULT_TOLERANCE_SECONDS, SIGNATURE_HEADER, WebhookError, constructEvent, customerSignInLimitReached, recoveryActionRequired, recoveryHolderDeclined, recoveryStatusChanged, verify } from '../src/webhook.js';

interface Vector {
  header_name: string;
  tolerance_seconds: number;
  secret: string;
  body: string;
  cases: { name: string; header: string; now: number; valid: boolean; error?: string; body?: string }[];
}
// The cases are the shared known answers in the fixtures. The first signature in them was made by the API's own code.
const vector = JSON.parse(fs.readFileSync('test/fixtures/v1/webhook-signature.json', 'utf8')) as Vector;

describe('webhook verify, against the shared known answers', () => {
  it('uses the header name and tolerance of the API', () => {
    expect(SIGNATURE_HEADER).toBe(vector.header_name);
    expect(DEFAULT_TOLERANCE_SECONDS).toBe(vector.tolerance_seconds);
  });

  for (const c of vector.cases) {
    it(c.name, () => {
      const run = () => verify(vector.secret, c.header, c.body ?? vector.body, { now: c.now });
      if (c.valid) expect(run).not.toThrow();
      else expect(run).toThrowError(expect.objectContaining({ name: 'WebhookError', code: c.error }));
    });
  }

  it('accepts the body as bytes too', () => {
    const good = vector.cases[0]!;
    expect(() => verify(vector.secret, good.header, Buffer.from(vector.body), { now: good.now })).not.toThrow();
  });
});

describe('constructEvent', () => {
  it('returns the event only after the signature checks', () => {
    const good = vector.cases[0]!;
    const event = constructEvent<{ id: string }>(vector.secret, good.header, vector.body, { now: good.now });
    expect(event.type).toBe('session.completed');
    expect(event.data.object.id).toBe('ses_1');
    expect(() => constructEvent(vector.secret, 't=1,v1=00', vector.body, { now: good.now })).toThrow(WebhookError);
  });
});

describe('recoveryStatusChanged', () => {
  const event = { id: 'evt_1', type: 'customer.recovery_status_changed', created: 1700000000, livemode: true,
    data: { object: { customer: 'cus_1', livemode: true, status: 'off', reason: 'device_lost', holders: 2, threshold: 2, changed_at: '2026-10-27T18:24:57Z' } } };

  it('reads the object of the event', () => {
    expect(recoveryStatusChanged(event)).toMatchObject({ status: 'off', reason: 'device_lost', holders: 2, threshold: 2, customer: 'cus_1' });
  });

  it('refuses another event type', () => {
    expect(() => recoveryStatusChanged({ ...event, type: 'session.completed' })).toThrow();
  });
});

describe('recoveryActionRequired', () => {
  const event = { id: 'evt_2', type: 'recovery.action_required', created: 1700000000, livemode: true,
    data: { object: { customer: 'cus_1', livemode: true, holder: 'h_1', holder_type: 'contact', reason: 'holder_added', requested_at: '2026-10-27T18:24:57Z' } } };

  it('reads the object of the event', () => {
    expect(recoveryActionRequired(event)).toMatchObject({ holder: 'h_1', holder_type: 'contact', reason: 'holder_added', customer: 'cus_1' });
  });

  it('refuses another event type', () => {
    expect(() => recoveryActionRequired({ ...event, type: 'customer.recovery_status_changed' })).toThrow();
  });
});

describe('recoveryHolderDeclined', () => {
  const event = { id: 'evt_3', type: 'recovery.holder_declined', created: 1700000000, livemode: true,
    data: { object: { customer: 'cus_1', livemode: true, holder: 'h_1', holder_type: 'contact', recovery: 'r_1', declined_at: '2026-10-27T18:24:57Z' } } };

  it('reads the object of the event', () => {
    expect(recoveryHolderDeclined(event)).toMatchObject({ holder: 'h_1', recovery: 'r_1', customer: 'cus_1' });
  });

  it('refuses another event type', () => {
    expect(() => recoveryHolderDeclined({ ...event, type: 'recovery.action_required' })).toThrow();
  });
});

describe('customerSignInLimitReached', () => {
  const event = { id: 'evt_4', type: 'customer.sign_in_limit_reached', created: 1700000000, livemode: true,
    data: { object: { customer: 'cus_1', livemode: true, brake: 'keyring_read', limit: 10, reached_at: '2026-10-29T10:00:00Z' } } };

  it('reads the object of the event', () => {
    expect(customerSignInLimitReached(event)).toMatchObject({ customer: 'cus_1', brake: 'keyring_read', limit: 10 });
  });

  it('refuses another event type', () => {
    expect(() => customerSignInLimitReached({ ...event, type: 'recovery.action_required' })).toThrow();
  });
});
