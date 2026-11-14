// Checks the webhooks Custodian sends to your server, and reads their events.
import crypto from 'node:crypto';

export const SIGNATURE_HEADER = 'Custodian-Signature';
export const DEFAULT_TOLERANCE_SECONDS = 300;

const MALFORMED_HEADER = 'the signature header is malformed';

export type WebhookErrorCode = 'header' | 'signature' | 'stale';

export class WebhookError extends Error {
  constructor(readonly code: WebhookErrorCode, message: string) {
    super(message);
    this.name = 'WebhookError';
  }
}

export interface VerifyOptions {
  /** How far the signature's time may be from `now`, in seconds. Default 300. */
  toleranceSeconds?: number;
  /** The current time in Unix seconds. Default: the clock. */
  now?: number;
}

/**
 * Checks the header against the raw request body, exactly as received (not parsed and re-written). Pass the endpoint's
 * secret (whsec_...). The header may hold several v1 signatures: one match is enough. The API signs with one
 * secret only, so after you rotate a secret, events fail until you deploy the new one.
 * Throws a WebhookError when the request must not be trusted.
 */
export function verify(secret: string, header: string, body: string | Uint8Array, options: VerifyOptions = {}): void {
  // An empty key would let anyone sign a forged event.
  if (!secret) throw new WebhookError('signature', 'the webhook secret is empty');
  const tolerance = options.toleranceSeconds && options.toleranceSeconds > 0 ? options.toleranceSeconds : DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Math.floor(Date.now() / 1000);

  let timestamp: number | undefined;
  const signatures: Buffer[] = [];
  for (const part of header.split(',')) {
    const trimmed = part.trim();
    const at = trimmed.indexOf('=');
    if (at < 0) throw new WebhookError('header', MALFORMED_HEADER);
    const key = trimmed.slice(0, at);
    const value = trimmed.slice(at + 1);
    if (key === 't') {
      if (!/^-?\d+$/.test(value)) throw new WebhookError('header', MALFORMED_HEADER);
      timestamp = Number(value);
    } else if (key === 'v1') {
      if (!/^([0-9a-fA-F]{2})*$/.test(value)) throw new WebhookError('header', MALFORMED_HEADER);
      signatures.push(Buffer.from(value, 'hex'));
    }
  }
  if (timestamp === undefined || signatures.length === 0) throw new WebhookError('header', MALFORMED_HEADER);

  const expected = crypto.createHmac('sha256', secret).update(`${timestamp}.`).update(body).digest();
  let matched = false;
  for (const signature of signatures) {
    // no early exit, so timing does not show which one matched
    if (signature.length === expected.length && crypto.timingSafeEqual(signature, expected)) matched = true;
  }
  if (!matched) throw new WebhookError('signature', 'the signature does not match');
  if (Math.abs(now - timestamp) > tolerance) throw new WebhookError('stale', 'the timestamp is outside the tolerance');
}

export interface WebhookEvent<T = unknown> {
  id: string;
  type: string;
  created: number;
  livemode: boolean;
  data: { object: T };
}

/**
 * Verifies the request and then reads its event. Call it first in your handler, with the raw body. The same event can arrive
 * more than once: ignore an id you have already handled.
 */
export function constructEvent<T = unknown>(secret: string, header: string, body: string | Uint8Array, options: VerifyOptions = {}): WebhookEvent<T> {
  verify(secret, header, body, options);
  return JSON.parse(typeof body === 'string' ? body : Buffer.from(body).toString('utf8')) as WebhookEvent<T>;
}

/** Event types that `observe` acts on. Not exported from the package. */
export const EVENT_CUSTOMER_ENROLLED = 'customer.enrolled';
export const EVENT_CUSTOMER_RESET = 'customer.reset';
export const EVENT_CUSTOMER_DELETED = 'customer.deleted';
export const EVENT_CUSTOMER_SIGN_IN_LIMIT_REACHED = 'customer.sign_in_limit_reached';

/** The object of a customer.sign_in_limit_reached event: a customer used the last slot of an hourly sign-in limit. Metadata only. */
export interface CustomerSignInLimitReached {
  customer: string;
  livemode: boolean;
  brake: 'sign_in_finish' | 'keyring_read' | 'failed_assertion';
  limit: number;
  reached_at: string;
}

/** Reads the object of a customer.sign_in_limit_reached event. Throws for any other event type. */
export function customerSignInLimitReached(event: WebhookEvent): CustomerSignInLimitReached {
  if (event.type !== EVENT_CUSTOMER_SIGN_IN_LIMIT_REACHED) throw new Error(`not a ${EVENT_CUSTOMER_SIGN_IN_LIMIT_REACHED} event`);
  return event.data.object as CustomerSignInLimitReached;
}
