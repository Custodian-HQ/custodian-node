import fs from 'node:fs';
import { describe, expect, it } from 'vitest';
import { Custodian } from '../src/custodian.js';
import {
  CustomerState,
  DisclosureKeyStatus,
  DisclosureStatus,
  Purpose,
  SessionStatus,
  WebhookDeliveryStatus,
  WebhookEndpointStatus,
  isCustomerState,
  isDisclosureStatus,
  isPurpose,
  isSessionStatus,
} from '../src/enums.js';

const ALL = { Purpose, SessionStatus, DisclosureStatus, DisclosureKeyStatus, WebhookEndpointStatus, WebhookDeliveryStatus, CustomerState };

/** Every list of values that the vendored API spec gives to a `purpose`, `status` or `state`, each as a sorted text. */
function specLists(): Set<string> {
  const text = fs.readFileSync('test/spec/openapi-vault.yaml', 'utf8');
  const lists = new Set<string>();
  for (const match of text.matchAll(/\b(?:purpose|status|state): \{ type: string, enum: \[([^\]]+)\] \}/g)) {
    lists.add(
      match[1]!
        .split(',')
        .map((name) => name.trim().replace(/^'|'$/g, ''))
        .sort()
        .join('|'),
    );
  }
  return lists;
}

const sorted = (list: Record<string, string>): string => Object.values(list).sort().join('|');

describe('the enums', () => {
  it('match the API spec exactly, in both directions', () => {
    const spec = specLists();
    expect(spec.size).toBeGreaterThan(4);
    for (const [name, list] of Object.entries(ALL)) {
      expect(spec.has(sorted(list)), `${name} is not a list of the spec`).toBe(true);
    }
    const ours = new Set(Object.values(ALL).map(sorted));
    for (const list of spec) expect(ours.has(list), `the spec has a list that the SDK lacks: ${list}`).toBe(true);
  });

  it('have a different name and a different text for every member', () => {
    for (const [name, list] of Object.entries(ALL)) {
      expect(new Set(Object.keys(list)).size, name).toBe(Object.keys(list).length);
      expect(new Set(Object.values(list)).size, name).toBe(Object.values(list).length);
    }
  });

  it('say whether a text is a known value', () => {
    expect(isPurpose('enrol')).toBe(true);
    expect(isPurpose(Purpose.RecoverySettings)).toBe(true);
    expect(isPurpose('device_link')).toBe(false);
    expect(isPurpose('')).toBe(false);
    expect(isSessionStatus('completed')).toBe(true);
    expect(isSessionStatus('done')).toBe(false);
    expect(isDisclosureStatus(DisclosureStatus.Approved)).toBe(true);
    expect(isCustomerState('reset: enrolment needed')).toBe(true);
    expect(isCustomerState('reset')).toBe(false);
  });

  it('are read back as the text the API sends', async () => {
    let body = '';
    const fetchImpl = async (_url: string | URL | Request, init?: RequestInit) => {
      body = String(init?.body);
      return new Response(JSON.stringify({ id: 'ses_1', purpose: 'recovery_settings', status: 'created' }), { status: 200, headers: { 'content-type': 'application/json' } });
    };
    const c = new Custodian('key', { fetch: fetchImpl as typeof fetch });
    const session = await c.sessions.create({ customer: 'cus_1', purpose: Purpose.RecoverySettings, return_url: 'https://a.example/x', state: 's' });
    expect(JSON.parse(body).purpose).toBe('recovery_settings');
    expect(session.purpose).toBe(Purpose.RecoverySettings);
    expect(session.status).toBe(SessionStatus.Created);
  });
});
