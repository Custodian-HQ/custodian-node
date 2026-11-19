// Reads the address the vault sent the customer back to.
import crypto from 'node:crypto';

/**
 * Returns the session id, trusting nothing else in the address. It needs `state` to be exactly the value your server
 * issued for this signed-in user. A `status` or any other parameter is ignored: anyone can type one. After this, call the
 * API for the session (`sessions.retrieve`) or wait for the webhook to learn what really happened.
 * Throws when the address cannot be used.
 */
export function parseReturn(returnUrl: string, expectedState: string): string {
  const bad = new Error('custodian: the return address is not valid for this request. Do not use it. Start a new session');
  if (expectedState === '') throw bad;
  let url: URL;
  try {
    url = new URL(returnUrl, 'https://placeholder.invalid');
  } catch {
    throw bad;
  }
  const sessions = url.searchParams.getAll('session');
  const states = url.searchParams.getAll('state');
  const session = sessions[0];
  const state = states[0];
  if (sessions.length !== 1 || states.length !== 1 || !session || state === undefined) throw bad;
  const a = Buffer.from(state);
  const b = Buffer.from(expectedState);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw bad;
  return session;
}

/**
 * Adds your disclosure key's fingerprint to the link of an approve session, in the fragment, so it never reaches the vault's server. Take the
 * fingerprint from your own app configuration (`fingerprint()` of your key), not from the vault: the vault page compares it with the key the
 * vault gives it, and stops the request if they differ. That check is what tells the customer the request is yours.
 * The address must use https. Plain http is allowed only for localhost, for local tests.
 */
export function approveUrl(sessionUrl: string, fingerprint: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(fingerprint)) throw new Error('custodian: the fingerprint must be 64 hexadecimal characters');
  let url: URL;
  try {
    url = new URL(sessionUrl);
  } catch {
    throw new Error('custodian: the session address is not valid');
  }
  const allowed = url.protocol === 'https:' || (url.protocol === 'http:' && url.hostname === 'localhost');
  if (url.hash.length < 2 || !allowed) throw new Error('custodian: the session address is not valid');
  const kept = url.hash.slice(1).split('&').filter((part) => part !== '' && part.split('=')[0] !== 'fp');
  return `${sessionUrl.slice(0, sessionUrl.indexOf('#'))}#${[...kept, `fp=${fingerprint.toLowerCase()}`].join('&')}`;
}
