import { resolveRef } from '../resolve.ts';
import type { Ctx, ProbeResult, Provisioned, Rotator, SecretDef } from '../types.ts';
import { http, probeFromStatus, readHidden, stamp, statusOf } from '../util.ts';
import { basic } from './probes.ts';

const API = 'https://api.stripe.com/v1';

export interface StripeSecretKeySpec {
	kind: 'stripe-secret-key';
	/** Store key (default STRIPE_SECRET_KEY). */
	key?: string;
}

export interface StripeWebhookSecretSpec {
	kind: 'stripe-webhook-secret';
	/** Store key for the signing secret (default STRIPE_WEBHOOK_SECRET). */
	key?: string;
	/** Store key for the API key that manages endpoints (default STRIPE_SECRET_KEY). */
	apiKey?: string;
	/** The endpoint URL, or `${KEY}` from the store. */
	url: string;
	/** Events for a brand-new endpoint; an existing one is cloned instead. */
	events?: string[];
	apiVersion?: string;
	description?: string;
}

function form(data: Record<string, string | string[]>): URLSearchParams {
	const p = new URLSearchParams();
	for (const [k, v] of Object.entries(data)) {
		if (Array.isArray(v)) v.forEach((x) => p.append(`${k}[]`, x));
		else p.append(k, v);
	}
	return p;
}

interface Account {
	id: string;
	settings?: { dashboard?: { display_name?: string } };
}

const account = (key: string) => http<Account>(`${API}/account`, { headers: basic(key) });

async function storeKey(ctx: Ctx, key: string): Promise<string> {
	const v = await ctx.store.get(key);
	if (!v) throw new Error(`${key} is not in the store`);
	return v;
}

/**
 * Stripe has no API for creating or rotating secret/restricted keys, so this
 * asks the operator to roll it in the Dashboard and paste the result, which is
 * checked against the same account and mode before it is accepted.
 */
export function stripeSecretKeyRotator(spec: StripeSecretKeySpec = { kind: 'stripe-secret-key' }): Rotator {
	const KEY = spec.key ?? 'STRIPE_SECRET_KEY';
	return {
		manual: true,
		async preflight(ctx) {
			const acct = await account(await storeKey(ctx, KEY));
			return [`Stripe key works for account ${acct.id} (${acct.settings?.dashboard?.display_name ?? 'live'})`];
		},
		async plan(ctx) {
			const key = await storeKey(ctx, KEY);
			const mode = key.includes('_live_') ? 'live' : 'test';
			return [
				`MANUAL: Stripe Dashboard (${mode} mode) → Developers → API keys → ⋯ on the current key → Roll key`,
				'  Choose an expiration; the grace period keeps the old key working until the revoke step',
				'  Prefer a restricted key (rk_) scoped to what the app uses over an unrestricted sk_',
				`paste the new key when prompted; it is probed against /v1/account and the account id before it is stored`,
				'old key: expires on its own after the grace period, or expire it now in the Dashboard (queued as a manual revoke)',
			];
		},
		async provision(ctx): Promise<Provisioned> {
			const oldKey = await storeKey(ctx, KEY);
			const oldAcct = await account(oldKey).catch(() => undefined);
			const value = await readHidden(`Paste the new Stripe secret/restricted key for ${KEY} (hidden): `);
			if (!/^(sk|rk)_(live|test)_[A-Za-z0-9]+$/.test(value)) throw new Error('That does not look like a Stripe secret or restricted key');
			if (oldKey.includes('_live_') !== value.includes('_live_')) throw new Error('New key is in a different mode (live/test) than the old one');
			const newAcct = await account(value);
			if (oldAcct && newAcct.id !== oldAcct.id) throw new Error(`New key belongs to ${newAcct.id}, the store key to ${oldAcct.id}`);
			return {
				values: { [KEY]: value },
				revoke: [
					{
						kind: 'manual',
						summary: `Stripe Dashboard → API keys: expire the previous key for ${newAcct.id} once its request log is quiet`,
					},
				],
			};
		},
		async probe(values): Promise<ProbeResult> {
			const key = values[KEY];
			if (!key) return { ok: false, detail: `${KEY} missing` };
			return probeFromStatus(await statusOf(`${API}/balance`, { headers: basic(key) }), 'stripe GET /v1/balance');
		},
	};
}

interface WebhookEndpoint {
	id: string;
	url: string;
	status: string;
	enabled_events: string[];
	api_version: string | null;
	secret?: string;
	livemode: boolean;
}

async function endpointsAt(key: string, url: string): Promise<WebhookEndpoint[]> {
	const page = await http<{ data: WebhookEndpoint[] }>(`${API}/webhook_endpoints?limit=100`, { headers: basic(key) });
	return page.data.filter((e) => e.url === url);
}

/**
 * Webhook signing secrets are only returned when an endpoint is created, so
 * rotation means: create a twin endpoint (same URL, events, API version), ship
 * its secret, then delete the old endpoint. While both exist the old one's
 * deliveries fail signature checks and Stripe retries them; harmless.
 */
export function stripeWebhookSecretRotator(spec: StripeWebhookSecretSpec): Rotator {
	const KEY = spec.key ?? 'STRIPE_WEBHOOK_SECRET';
	const API_KEY = spec.apiKey ?? 'STRIPE_SECRET_KEY';
	const url = (ctx: Ctx) => resolveRef(spec.url, ctx, 'stripe webhook url');
	return {
		async preflight(ctx) {
			const u = await url(ctx);
			const existing = await endpointsAt(await storeKey(ctx, API_KEY), u);
			return [`${existing.length} webhook endpoint(s) at ${u}: ${existing.map((e) => `${e.id} ${e.status}`).join(', ') || 'none'}`];
		},
		async plan(ctx) {
			const u = await url(ctx);
			const existing = await endpointsAt(await storeKey(ctx, API_KEY), u);
			const t = existing[0];
			return [
				`POST ${API}/webhook_endpoints url=${u} events=[${(t?.enabled_events ?? spec.events ?? []).join(', ')}] api_version=${t?.api_version ?? spec.apiVersion ?? 'account default'}`,
				...existing.map((e) => `then delete old endpoint ${e.id} (${e.status}) once the new secret is deployed`),
				...(existing.length === 0 ? ['no existing endpoint at that URL; nothing would be deleted'] : []),
			];
		},
		async provision(ctx): Promise<Provisioned> {
			const key = await storeKey(ctx, API_KEY);
			const u = await url(ctx);
			const existing = await endpointsAt(key, u);
			const t = existing[0];
			const events = t?.enabled_events ?? spec.events;
			if (!events?.length) throw new Error('no existing endpoint to clone and no `events` in the manifest');
			const created = await http<WebhookEndpoint>(`${API}/webhook_endpoints`, {
				method: 'POST',
				headers: { ...basic(key), 'content-type': 'application/x-www-form-urlencoded' },
				body: form({
					url: u,
					enabled_events: events,
					...(t?.api_version ?? spec.apiVersion ? { api_version: (t?.api_version ?? spec.apiVersion)! } : {}),
					description: spec.description ?? `rotated ${stamp()}`,
				}),
			});
			if (!created.secret) throw new Error('Stripe did not return the webhook secret');
			return {
				values: { [KEY]: created.secret },
				revoke: existing.map((e) => ({ kind: 'stripe-webhook-endpoint', summary: `delete Stripe webhook endpoint ${e.id} (${u})`, id: e.id })),
			};
		},
		async probe(values, ctx): Promise<ProbeResult> {
			const secret = values[KEY];
			if (!secret?.startsWith('whsec_')) return { ok: false, detail: `${KEY} missing or malformed` };
			const key = values[API_KEY] ?? (await storeKey(ctx, API_KEY));
			const enabled = (await endpointsAt(key, await url(ctx))).filter((e) => e.status === 'enabled');
			return { ok: enabled.length >= 1, detail: `${enabled.length} enabled endpoint(s) at the webhook URL (a signature needs a live event to test)` };
		},
		async revoke(d, ctx) {
			await http(`${API}/webhook_endpoints/${String(d.id)}`, { method: 'DELETE', headers: basic(await storeKey(ctx, API_KEY)) });
		},
	};
}

export type { SecretDef };
