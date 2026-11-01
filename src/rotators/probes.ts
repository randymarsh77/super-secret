import type { Ctx, ProbeResult, SecretDef, Values } from '../types.ts';
import { interpolate, probeFromStatus, statusOf } from '../util.ts';
import { RAILWAY_GQL } from '../targets/railway.ts';

/**
 * How to tell that a value works. `http` is the general form; the named
 * presets are the cheapest authenticated call each provider offers.
 * `key` names the store key holding the credential (default: the secret's
 * first key).
 */
export type ProbeSpec =
	| { kind: 'none' }
	| {
			kind: 'http';
			url: string;
			method?: string;
			/** Header values may use `${KEY}` from the values being probed. */
			headers?: Record<string, string>;
			/** Basic auth: the key whose value is the username (password empty), or both. */
			basic?: string | { user: string; pass: string };
			/** Bearer auth from this key. */
			bearer?: string;
			body?: string;
			expect?: number | number[];
	  }
	| { kind: PresetName; key?: string };

export type PresetName = keyof typeof PRESETS;

type Preset = (value: string) => Promise<ProbeResult>;

async function json<T>(url: string, init: RequestInit): Promise<{ status: number; body?: T }> {
	try {
		const res = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) });
		const text = await res.text();
		let body: T | undefined;
		try {
			body = JSON.parse(text) as T;
		} catch {
			/* not JSON */
		}
		return { status: res.status, body };
	} catch {
		return { status: 0 };
	}
}

export const PRESETS = {
	'railway-account': async (token) => {
		const r = await json<{ data?: { me?: { email?: string } } }>(RAILWAY_GQL, {
			method: 'POST',
			headers: { 'content-type': 'application/json', authorization: `Bearer ${token}` },
			body: JSON.stringify({ query: '{ me { email } }' }),
		});
		const email = r.body?.data?.me?.email;
		return { ok: !!email, detail: email ? `railway account ${email}` : `railway me → HTTP ${r.status}, not authorized` };
	},
	'railway-project': async (token) => {
		const r = await json<{ data?: { projectToken?: { projectId?: string } } }>(RAILWAY_GQL, {
			method: 'POST',
			headers: { 'content-type': 'application/json', 'project-access-token': token },
			body: JSON.stringify({ query: '{ projectToken { projectId environmentId } }' }),
		});
		const id = r.body?.data?.projectToken?.projectId;
		return { ok: !!id, detail: id ? `railway project token for ${id}` : `railway projectToken → HTTP ${r.status}, not authorized` };
	},
	'github-token': async (token) => {
		const r = await json<{ login?: string }>('https://api.github.com/user', {
			headers: { authorization: `Bearer ${token}`, 'user-agent': 'super-secret' },
		});
		return { ok: r.status === 200, detail: r.status === 200 ? `github user ${r.body?.login}` : `GET /user → HTTP ${r.status}` };
	},
	'stripe-key': async (key) =>
		probeFromStatus(await statusOf('https://api.stripe.com/v1/balance', { headers: basic(key) }), 'stripe GET /v1/balance'),
	anthropic: async (key) =>
		probeFromStatus(
			await statusOf('https://api.anthropic.com/v1/models?limit=1', { headers: { 'x-api-key': key, 'anthropic-version': '2023-06-01' } }),
			'anthropic GET /v1/models'
		),
	openai: async (key) =>
		probeFromStatus(await statusOf('https://api.openai.com/v1/models', { headers: bearer(key) }), 'openai GET /v1/models'),
	openrouter: async (key) =>
		probeFromStatus(await statusOf('https://openrouter.ai/api/v1/auth/key', { headers: bearer(key) }), 'openrouter GET /auth/key'),
	sentry: async (token) =>
		probeFromStatus(await statusOf('https://sentry.io/api/0/organizations/', { headers: bearer(token) }), 'sentry GET /organizations/'),
	/** Resend restricts send-only keys from every read endpoint; an empty send is 4xx-validated only when the key is good. */
	resend: async (key) =>
		probeFromStatus(
			await statusOf('https://api.resend.com/emails', { method: 'POST', headers: { ...bearer(key), 'content-type': 'application/json' }, body: '{}' }),
			'resend POST /emails (empty)',
			[400, 422]
		),
	synoptic: async (token) => {
		const r = await json<{ SUMMARY?: { RESPONSE_CODE?: number; RESPONSE_MESSAGE?: string } }>(
			`https://api.synopticdata.com/v2/stations/metadata?token=${encodeURIComponent(token)}&stid=KBLI`,
			{}
		);
		const code = r.body?.SUMMARY?.RESPONSE_CODE;
		return { ok: r.status === 200 && code === 1, detail: `synoptic → HTTP ${r.status}, RESPONSE_CODE ${code ?? '?'}` };
	},
	'cloudflare-token': async (token) => {
		const r = await json<{ result?: { status?: string } }>('https://api.cloudflare.com/client/v4/user/tokens/verify', {
			headers: bearer(token),
		});
		const status = r.body?.result?.status;
		return { ok: status === 'active', detail: `cloudflare tokens/verify → HTTP ${r.status}, status ${status ?? '?'}` };
	},
} satisfies Record<string, Preset>;

export function basic(user: string, pass = ''): Record<string, string> {
	return { authorization: `Basic ${Buffer.from(`${user}:${pass}`).toString('base64')}` };
}
export function bearer(token: string): Record<string, string> {
	return { authorization: `Bearer ${token}` };
}

export async function runProbe(spec: ProbeSpec | undefined, values: Values, ctx: Ctx, def: SecretDef): Promise<ProbeResult> {
	if (!spec || spec.kind === 'none') return { ok: true, detail: 'no probe defined' };
	if (spec.kind === 'http') {
		// fall back to the store for keys the new values do not carry (a URL's companion key)
		const all: Values = { ...values };
		for (const k of def.keys) if (!(k in all)) all[k] = (await ctx.store.get(k)) ?? '';
		const headers: Record<string, string> = {};
		for (const [h, v] of Object.entries(spec.headers ?? {})) headers[h] = interpolate(v, all);
		if (spec.bearer) Object.assign(headers, bearer(all[spec.bearer] ?? ''));
		if (spec.basic)
			Object.assign(
				headers,
				typeof spec.basic === 'string' ? basic(all[spec.basic] ?? '') : basic(all[spec.basic.user] ?? '', all[spec.basic.pass] ?? '')
			);
		const status = await statusOf(interpolate(spec.url, all), { method: spec.method ?? 'GET', headers, body: spec.body });
		return probeFromStatus(status, `${spec.method ?? 'GET'} ${spec.url}`, spec.expect ?? 200);
	}
	const key = spec.key ?? def.keys[0]!;
	const value = values[key] ?? (await ctx.store.get(key));
	if (!value) return { ok: false, detail: `${key} missing` };
	const preset = PRESETS[spec.kind] as Preset | undefined;
	if (!preset) return { ok: false, detail: `unknown probe ${String(spec.kind)}` };
	return preset(value);
}
