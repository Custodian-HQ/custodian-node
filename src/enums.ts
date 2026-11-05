// The fixed lists of text values of the API. Use these names instead of writing the text by hand.
// Each list is a plain object, and the type of the same name is the union of its values.
// A newer API can send a value that this library does not know yet: the `is...` functions check that.

/** The values this library knows, and any other text a newer API may send. */
export type Open<T extends string> = T | (string & Record<never, never>);

/** True when the text is one of the values of the list. */
function isValueOf<T extends Record<string, string>>(list: T, text: string): text is T[keyof T] {
  return (Object.values(list) as string[]).includes(text);
}

/** What a session is for. */
export const Purpose = {
  Enrol: 'enrol',
  Entry: 'entry',
  View: 'view',
  Approve: 'approve',
  Recover: 'recover',
  RecoverySettings: 'recovery_settings',
  Reset: 'reset',
  Delete: 'delete',
  Holder: 'holder',
} as const;
export type Purpose = (typeof Purpose)[keyof typeof Purpose];
export const isPurpose = (text: string): text is Purpose => isValueOf(Purpose, text);

/** Where a session is in its life. */
export const SessionStatus = {
  Created: 'created',
  Exchanged: 'exchanged',
  Completed: 'completed',
  Cancelled: 'cancelled',
  Expired: 'expired',
} as const;
export type SessionStatus = (typeof SessionStatus)[keyof typeof SessionStatus];
export const isSessionStatus = (text: string): text is SessionStatus => isValueOf(SessionStatus, text);

/** Where a disclosure request is in its life. */
export const DisclosureStatus = {
  Pending: 'pending',
  Approved: 'approved',
  Rejected: 'rejected',
  Cancelled: 'cancelled',
  Expired: 'expired',
} as const;
export type DisclosureStatus = (typeof DisclosureStatus)[keyof typeof DisclosureStatus];
export const isDisclosureStatus = (text: string): text is DisclosureStatus => isValueOf(DisclosureStatus, text);

/** Whether a disclosure key is in use, being replaced, or no longer used. */
export const DisclosureKeyStatus = {
  Active: 'active',
  Retiring: 'retiring',
  Retired: 'retired',
} as const;
export type DisclosureKeyStatus = (typeof DisclosureKeyStatus)[keyof typeof DisclosureKeyStatus];
export const isDisclosureKeyStatus = (text: string): text is DisclosureKeyStatus => isValueOf(DisclosureKeyStatus, text);

/** Whether a webhook endpoint receives events. */
export const WebhookEndpointStatus = {
  Enabled: 'enabled',
  Disabled: 'disabled',
} as const;
export type WebhookEndpointStatus = (typeof WebhookEndpointStatus)[keyof typeof WebhookEndpointStatus];
export const isWebhookEndpointStatus = (text: string): text is WebhookEndpointStatus => isValueOf(WebhookEndpointStatus, text);

/** Where one webhook delivery is. */
export const WebhookDeliveryStatus = {
  Pending: 'pending',
  Retrying: 'retrying',
  Delivered: 'delivered',
  Failed: 'failed',
} as const;
export type WebhookDeliveryStatus = (typeof WebhookDeliveryStatus)[keyof typeof WebhookDeliveryStatus];
export const isWebhookDeliveryStatus = (text: string): text is WebhookDeliveryStatus => isValueOf(WebhookDeliveryStatus, text);

/** Whether a customer can use their vault, or must enrol again after a reset. */
export const CustomerState = {
  Active: 'active',
  ResetEnrolmentNeeded: 'reset: enrolment needed',
} as const;
export type CustomerState = (typeof CustomerState)[keyof typeof CustomerState];
export const isCustomerState = (text: string): text is CustomerState => isValueOf(CustomerState, text);
