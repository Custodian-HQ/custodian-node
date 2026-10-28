// Checks the webhooks Custodian sends to your server, and reads their events.
import crypto from 'node:crypto';

export const SIGNATURE_HEADER = 'Custodian-Signature';
export const DEFAULT_TOLERANCE_SECONDS = 300;

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
 * secret (whsec_...). The header may hold several v1 signatures, during a secret rotation: one match is enough.
 * Throws a WebhookError when the request must not be trusted.
 */
export function verify(secret: string, header: string, body: string | Uint8Array, options: VerifyOptions = {}): void {
  const tolerance = options.toleranceSeconds && options.toleranceSeconds > 0 ? options.toleranceSeconds : DEFAULT_TOLERANCE_SECONDS;
  const now = options.now ?? Math.floor(Date.now() / 1000);

  let timestamp: number | undefined;
  const signatures: Buffer[] = [];
  for (const part of header.split(',')) {
    const trimmed = part.trim();
    const at = trimmed.indexOf('=');
    if (at < 0) throw new WebhookError('header', 'the signature header is malformed');
    const key = trimmed.slice(0, at);
    const value = trimmed.slice(at + 1);
    if (key === 't') {
      if (!/^-?\d+$/.test(value)) throw new WebhookError('header', 'the signature header is malformed');
      timestamp = Number(value);
    } else if (key === 'v1') {
      if (!/^([0-9a-fA-F]{2})*$/.test(value)) throw new WebhookError('header', 'the signature header is malformed');
      signatures.push(Buffer.from(value, 'hex'));
    }
  }
  if (timestamp === undefined || signatures.length === 0) throw new WebhookError('header', 'the signature header is malformed');

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

export const EVENT_RECOVERY_STATUS_CHANGED = 'customer.recovery_status_changed';

/**
 * The object of a customer.recovery_status_changed event: share recovery turned on or off for a customer. Metadata only. `reason` is a
 * code such as holder_removed, device_lost, holder_enrolled or secret_recovery; do not depend on the list being closed. `holders` counts
 * the holders with keys after the change.
 */
export interface RecoveryStatusChanged {
  customer: string;
  livemode: boolean;
  status: 'on' | 'off';
  reason: string;
  holders: number;
  threshold: number;
  changed_at: string;
}

/** Reads the object of a customer.recovery_status_changed event. Throws for any other event type. */
export function recoveryStatusChanged(event: WebhookEvent): RecoveryStatusChanged {
  if (event.type !== EVENT_RECOVERY_STATUS_CHANGED) throw new Error(`not a ${EVENT_RECOVERY_STATUS_CHANGED} event`);
  return event.data.object as RecoveryStatusChanged;
}

export const EVENT_RECOVERY_ACTION_REQUIRED = 'recovery.action_required';

/**
 * The object of a recovery.action_required event: the customer must unlock recovery settings so the shares are dealt again. Metadata only.
 * `reason` is a code such as holder_added, holder_removed or device_lost; do not depend on the list being closed.
 */
export interface RecoveryActionRequired {
  customer: string;
  livemode: boolean;
  holder: string;
  holder_type: 'contact' | 'device';
  reason: string;
  requested_at: string;
}

/** Reads the object of a recovery.action_required event. Throws for any other event type. */
export function recoveryActionRequired(event: WebhookEvent): RecoveryActionRequired {
  if (event.type !== EVENT_RECOVERY_ACTION_REQUIRED) throw new Error(`not a ${EVENT_RECOVERY_ACTION_REQUIRED} event`);
  return event.data.object as RecoveryActionRequired;
}

export const EVENT_RECOVERY_HOLDER_DECLINED = 'recovery.holder_declined';

/** The object of a recovery.holder_declined event: a trusted contact did not expect a release request and declined it. Metadata only; other holders' requests stay open. */
export interface RecoveryHolderDeclined {
  customer: string;
  livemode: boolean;
  holder: string;
  holder_type: 'contact';
  recovery: string;
  declined_at: string;
}

/** Reads the object of a recovery.holder_declined event. Throws for any other event type. */
export function recoveryHolderDeclined(event: WebhookEvent): RecoveryHolderDeclined {
  if (event.type !== EVENT_RECOVERY_HOLDER_DECLINED) throw new Error(`not a ${EVENT_RECOVERY_HOLDER_DECLINED} event`);
  return event.data.object as RecoveryHolderDeclined;
}
