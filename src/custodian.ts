// The Custodian Data Vault client, with a method for every operation of the business API.
import { Client, type ClientOptions, type RequestOptions } from './client.js';

export interface Customer {
  id: string;
  external_ref: string;
  livemode: boolean;
  state: string;
  enrolled: boolean;
  /** The customer's public signing key, base64url. Keep the one from the customer.enrolled webhook and check envelopes against that; do not rely on this field alone. */
  vault_sign_key?: string;
  /** The name you offered, until the customer confirms or corrects it at enrolment (`name_confirmed`). After that you cannot change it. */
  first_name?: string;
  last_name?: string;
  name_confirmed: boolean;
  created_at: string;
  /** When the customer last confirmed a reset. Missing if never. While `state` is `reset: enrolment needed`, the customer must enrol again. */
  reset_at?: string;
}

/** Who started a reset, as the `customer.reset` webhook says it. */
export type ResetInitiatedBy = 'business' | 'customer_request';

/** The object of the `customer.reset_requested` webhook. The customer asked for a reset; nothing was deleted. At most 3 per customer per day. */
export interface CustomerResetRequestedEvent {
  id: string;
  external_ref: string;
  livemode: boolean;
  requested_at: string;
}

/** The object of the `customer.reset` webhook. `initiated_by` is `customer_request` if a `customer.reset_requested` came before for this customer. */
export interface CustomerResetEvent {
  id: string;
  external_ref: string;
  livemode: boolean;
  reset_at: string;
  initiated_by: ResetInitiatedBy;
}
export interface CustomerPage {
  data: Customer[];
  has_more: boolean;
}
export interface Key {
  name: string;
  label?: string;
  type?: 'text' | 'number' | 'date' | 'email' | 'phone' | 'file';
  /** The largest file for this key, in bytes. Only a file key may set it. Leave it out to use your plan's limit; it cannot be larger. */
  max_size?: number;
  /** File keys only: the MIME types the key takes. Leave it out to take every type the server allows. */
  accept?: string[];
}
export type Purpose = 'enrol' | 'entry' | 'view' | 'approve' | 'recover' | 'recovery_settings' | 'reset' | 'delete' | 'holder';
export interface CreateSessionParams {
  customer: string;
  purpose: Purpose;
  /** One of the addresses you registered for the key's mode. */
  return_url: string;
  /** Required. A value you can tie to your signed-in user; check it when the customer returns. */
  state: string;
  template?: string;
  keys?: Key[];
  /** The record token. A view needs it. An entry may name one to add keys to that record. */
  record?: string;
  disclosure?: string;
}
export interface Session {
  id: string;
  customer: string;
  purpose: string;
  status: 'created' | 'exchanged' | 'completed' | 'cancelled' | 'expired';
  livemode: boolean;
  return_url: string;
  state: string;
  expires_at: string;
  created_at: string;
  completed_at?: string;
  cancelled_at?: string;
  /** The record this visit added to or shows. For an entry that makes a new record, it is set once the customer saved. */
  record?: string;
  /** Only in the answer that creates the session. Send the customer here. */
  url?: string;
  warnings?: string[];
}
/** A key of a record: its name, label, type and version. You never see a value. */
export interface KeySummary {
  name: string;
  label?: string;
  type: string;
  version: number;
  updated_at: string;
}
/** What a customer keeps with you, as you see it: the token and the key names. */
export interface CustomerRecord {
  token: string;
  customer: string;
  version: number;
  keys: KeySummary[];
  created_at: string;
  updated_at: string;
}
export interface RecordPage {
  data: CustomerRecord[];
  has_more: boolean;
}
export interface Template {
  name: string;
  keys: Key[];
  warnings?: string[];
}
export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string[];
  livemode: boolean;
  status: 'enabled' | 'disabled';
  created_at: string;
  /** Only when the endpoint is made or its secret is rotated. Store it then. */
  secret?: string;
}
export interface WebhookDelivery {
  id: number;
  endpoint: string;
  event: string;
  type: string;
  status: 'pending' | 'retrying' | 'delivered' | 'failed';
  attempts: number;
  last_status?: number;
  last_error?: string;
  created_at: string;
  completed_at?: string;
}
export interface Usage {
  from: string;
  to: string;
  livemode: boolean;
  customers: number;
  enrolled_customers: number;
  records: number;
  sessions: number;
  disclosures: number;
}
export interface AuditEvent {
  id: number;
  type: string;
  occurred_at: string;
  user?: string;
  api_key?: string;
  payload?: Record<string, unknown>;
}

const enc = encodeURIComponent;

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== '') search.set(key, String(value));
  const text = search.toString();
  return text ? `?${text}` : '';
}

/** A public key you receive disclosures with. `fingerprint` is not a secret: keep it in your app config. */
export interface RegisteredDisclosureKey {
  id: string;
  name: string;
  suite: string;
  public_key: string;
  fingerprint: string;
  fingerprint_short: string;
  status: 'active' | 'retiring' | 'retired';
  livemode: boolean;
  registered_at: string;
  retires_at: string | null;
  retired_at: string | null;
}

/** Send `customer`, `record`, or both. With both, the record must belong to the customer. With only `customer`, the customer's one record that holds every key is used. */
export interface CreateDisclosureParams {
  customer?: string;
  record?: string;
  keys: string[];
  reason: string;
  /** Seconds the request waits for the customer. From 60 to 259200. The default is 900. */
  expires_in?: number;
  /** The fingerprint of your disclosure key. */
  disclosure_key_fingerprint: string;
}

export type DisclosureStatus = 'pending' | 'approved' | 'rejected' | 'cancelled' | 'expired';

/** A request to see named keys of one record. It holds names only, never values. */
export interface Disclosure {
  id: string;
  record: string;
  customer: string;
  keys: string[];
  reason: string;
  status: DisclosureStatus;
  livemode: boolean;
  disclosure_key: string;
  expires_at: string;
  decided_at: string | null;
  /** When you acknowledged the envelope. The vault deleted it then. */
  acked_at: string | null;
  /** True while you can still fetch the envelope. */
  envelope_ready: boolean;
  created_at: string;
}

export interface DisclosurePage {
  data: Disclosure[];
  has_more: boolean;
}

export class Custodian {
  readonly #client: Client;

  constructor(apiKey: string, options: ClientOptions = {}) {
    this.#client = new Client(apiKey, options);
  }

  /** Whose key this is. A good first call. */
  me(): Promise<{ organization: string; name: string; livemode: boolean }> {
    return this.#client.request('GET', '/me');
  }

  readonly customers = {
    create: (externalRef: string, options?: RequestOptions): Promise<Customer> =>
      this.#client.request('POST', '/customers', { external_ref: externalRef }, options),
    /** Makes a customer with the name you offer for them (1 to 60 characters each). The customer confirms or corrects it at enrolment. */
    createNamed: (externalRef: string, name: { first_name: string; last_name: string }, options?: RequestOptions): Promise<Customer> =>
      this.#client.request('POST', '/customers', { external_ref: externalRef, ...name }, options),
    get: (id: string): Promise<Customer> => this.#client.request('GET', `/customers/${enc(id)}`),
    /** Deletes the customer and all their data at once. It cannot be undone, and the customer is not asked. */
    delete: async (id: string): Promise<void> => {
      await this.#client.request('DELETE', `/customers/${enc(id)}`);
    },
    /**
     * Starts a reset of a customer who has lost every way in. Nothing is deleted until the customer confirms on the page at `url` in the
     * answer. Then all their data is deleted for good, and they enrol again.
     */
    reset: (id: string, params: { return_url: string; state: string }, options?: RequestOptions): Promise<Session> =>
      this.#client.request('POST', `/customers/${enc(id)}/reset`, params, options),
    list: (params: { limit?: number; starting_after?: string; external_ref?: string; state?: 'active' | 'reset: enrolment needed' } = {}): Promise<CustomerPage> =>
      this.#client.request('GET', '/customers' + query(params)),
  };

  readonly sessions = {
    /** Starts a visit. Send the customer to `url` in the answer: it is shown once. */
    create: (params: CreateSessionParams, options?: RequestOptions): Promise<Session> => this.#client.request('POST', '/sessions', params, options),
    /** Where a visit stands. Use this, or a webhook, to learn the result: never trust the address the customer returns to. */
    retrieve: (id: string): Promise<Session> => this.#client.request('GET', `/sessions/${enc(id)}`),
  };

  readonly records = {
    /** Lists a customer's records, newest first: tokens and key names, never values. */
    list: (params: { customer: string; limit?: number; starting_after?: string }): Promise<RecordPage> => this.#client.request('GET', '/records' + query(params)),
    get: (token: string): Promise<CustomerRecord> => this.#client.request('GET', `/records/${enc(token)}`),
  };

  readonly templates = {
    list: async (): Promise<Template[]> => (await this.#client.request<{ data: Template[] }>('GET', '/templates')).data,
    create: (template: Template): Promise<Template> => this.#client.request('POST', '/templates', template),
    get: (name: string): Promise<Template> => this.#client.request('GET', `/templates/${enc(name)}`),
    replace: (name: string, keys: Key[]): Promise<Template> => this.#client.request('PUT', `/templates/${enc(name)}`, { keys }),
    delete: async (name: string): Promise<void> => {
      await this.#client.request('DELETE', `/templates/${enc(name)}`);
    },
  };

  /** Keys are registered and retired in the Console, where a member confirms with a code. This API cannot change them. */
  readonly disclosureKeys = {
    list: async (): Promise<RegisteredDisclosureKey[]> => (await this.#client.request<{ data: RegisteredDisclosureKey[] }>('GET', '/disclosure-keys')).data,
  };

  readonly disclosures = {
    /** Asks one customer to let you see named keys. Then start a session with the `approve` purpose and this id. */
    create: (params: CreateDisclosureParams, options?: RequestOptions): Promise<Disclosure> => this.#client.request('POST', '/disclosures', params, options),
    get: (id: string): Promise<Disclosure> => this.#client.request('GET', `/disclosures/${enc(id)}`),
    list: (params: { status?: DisclosureStatus; limit?: number; starting_after?: string } = {}): Promise<DisclosurePage> =>
      this.#client.request('GET', '/disclosures' + query(params)),
    cancel: (id: string): Promise<Disclosure> => this.#client.request('POST', `/disclosures/${enc(id)}/cancel`),
    /** Fetches the sealed values of an approved request, as the vault sent them. Open it with `openEnvelope`, then `acknowledge`. You have 15 minutes. */
    envelope: (id: string): Promise<Record<string, unknown>> => this.#client.request('GET', `/disclosures/${enc(id)}/envelope`),
    /** Tells the vault that you have the envelope and opened it. The vault deletes it. Safe to call twice. */
    acknowledge: (id: string): Promise<Disclosure> => this.#client.request('POST', `/disclosures/${enc(id)}/ack`),
  };

  readonly recoveryPolicy = {
    get: (): Promise<{ recovery_threshold: number }> => this.#client.request('GET', '/recovery-policy'),
    set: (threshold: number): Promise<{ recovery_threshold: number }> => this.#client.request('PUT', '/recovery-policy', { recovery_threshold: threshold }),
  };

  /** The text a customer reads after they ask you for a reset. The default is "Contact the business that gave you this link". */
  readonly resetContactText = {
    get: (): Promise<{ text: string }> => this.#client.request('GET', '/reset-contact-text'),
    /** Plain text, 1 to 200 characters. The customer always has the button to ask; you cannot turn it off. */
    set: (text: string): Promise<{ text: string }> => this.#client.request('PUT', '/reset-contact-text', { text }),
  };

  readonly webhookEndpoints = {
    create: (url: string, events: string[], options?: RequestOptions): Promise<WebhookEndpoint> =>
      this.#client.request('POST', '/webhook-endpoints', { url, events }, options),
    list: async (): Promise<WebhookEndpoint[]> => (await this.#client.request<{ data: WebhookEndpoint[] }>('GET', '/webhook-endpoints')).data,
    update: (id: string, changes: { url?: string; events?: string[]; status?: 'enabled' | 'disabled' }): Promise<WebhookEndpoint> =>
      this.#client.request('PUT', `/webhook-endpoints/${enc(id)}`, changes),
    delete: async (id: string): Promise<void> => {
      await this.#client.request('DELETE', `/webhook-endpoints/${enc(id)}`);
    },
    /** The old secret stops working at once. */
    rotateSecret: (id: string): Promise<WebhookEndpoint> => this.#client.request('POST', `/webhook-endpoints/${enc(id)}/rotate-secret`),
  };

  readonly webhookDeliveries = {
    list: async (params: { endpoint?: string; limit?: number; starting_after?: number } = {}): Promise<WebhookDelivery[]> =>
      (await this.#client.request<{ data: WebhookDelivery[] }>('GET', '/webhook-deliveries' + query(params))).data,
    retry: async (id: number): Promise<void> => {
      await this.#client.request('POST', `/webhook-deliveries/${id}/retry`);
    },
  };

  /** What you used in a period. No dates means this month so far. */
  usage(params: { from?: string; to?: string } = {}): Promise<Usage> {
    return this.#client.request('GET', '/usage' + query(params));
  }

  auditEvents = async (params: { limit?: number; starting_after?: number } = {}): Promise<AuditEvent[]> =>
    (await this.#client.request<{ data: AuditEvent[] }>('GET', '/audit-events' + query(params))).data;
}
