import type { Provisioned, Rotator } from '../types.ts';
import { http, HttpError } from '../util.ts';
import { PRESETS, bearer } from './probes.ts';

export interface CloudflareApiTokenSpec {
	kind: 'cloudflare-api-token';
	/** Store key (default CLOUDFLARE_API_TOKEN). */
	key?: string;
}

const API = 'https://api.cloudflare.com/client/v4';

/**
 * Cloudflare can roll a token's value in place (PUT /user/tokens/:id/value)
 * when the caller may edit API tokens. The token rolls itself: same id, same
 * permissions, new secret; nothing to revoke. Without that permission the
 * call fails and the manifest should use a `manual` rotator instead.
 */
export function cloudflareApiTokenRotator(spec: CloudflareApiTokenSpec = { kind: 'cloudflare-api-token' }): Rotator {
	const KEY = spec.key ?? 'CLOUDFLARE_API_TOKEN';
	return {
		async preflight(ctx) {
			const token = await ctx.store.get(KEY);
			if (!token) throw new Error(`${KEY} is not in the store`);
			const r = await PRESETS['cloudflare-token'](token);
			if (!r.ok) throw new Error(r.detail);
			return [r.detail];
		},
		async plan() {
			return [
				`GET ${API}/user/tokens/verify for the token id, then PUT /user/tokens/{id}/value (roll in place)`,
				'needs the token (or the operator env) to carry "API Tokens: Edit"; otherwise use a manual rotator',
				'nothing to revoke: the old value stops working the moment the roll returns',
			];
		},
		async provision(ctx): Promise<Provisioned> {
			const token = await ctx.store.get(KEY);
			if (!token) throw new Error(`${KEY} is not in the store`);
			const verify = await http<{ result: { id: string } }>(`${API}/user/tokens/verify`, { headers: bearer(token) });
			try {
				const rolled = await http<{ result: string }>(`${API}/user/tokens/${verify.result.id}/value`, {
					method: 'PUT',
					headers: { ...bearer(token), 'content-type': 'application/json' },
					body: '{}',
				});
				return { values: { [KEY]: rolled.result }, revoke: [], notes: [`rolled token ${verify.result.id}`] };
			} catch (e) {
				if (e instanceof HttpError && (e.status === 403 || e.status === 401))
					throw new Error(`token ${verify.result.id} may not roll itself (HTTP ${e.status}); give it "User → API Tokens → Edit" or switch this secret to a manual rotator`);
				throw e;
			}
		},
		async probe(values) {
			const v = values[KEY];
			return v ? PRESETS['cloudflare-token'](v) : { ok: false, detail: `${KEY} missing` };
		},
	};
}
