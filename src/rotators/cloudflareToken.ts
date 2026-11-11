import { resolveRef } from '../resolve.ts';
import type { Ctx, Provisioned, Rotator } from '../types.ts';
import { http, HttpError } from '../util.ts';
import { bearer, locateCloudflareToken } from './probes.ts';

export interface CloudflareApiTokenSpec {
	kind: 'cloudflare-api-token';
	/** Store key (default CLOUDFLARE_API_TOKEN). */
	key?: string;
	/**
	 * Account id for an account-owned token: a literal or `${KEY}`. Optional:
	 * without it the account is discovered with the token itself. Ignored for
	 * a user-owned token.
	 */
	account?: string;
}

/**
 * Cloudflare can roll a token's value in place (PUT …/tokens/:id/value) when
 * the caller may edit API tokens. The token rolls itself: same id, same
 * permissions, new secret; nothing to revoke. User-owned and account-owned
 * tokens roll at different endpoints (/user/tokens vs /accounts/{id}/tokens);
 * the rotator finds out which kind it holds. Without the edit permission the
 * call fails and the manifest should use a `manual` rotator instead.
 */
export function cloudflareApiTokenRotator(spec: CloudflareApiTokenSpec = { kind: 'cloudflare-api-token' }): Rotator {
	const KEY = spec.key ?? 'CLOUDFLARE_API_TOKEN';
	const account = async (ctx: Ctx) => (spec.account ? resolveRef(spec.account, ctx, 'cloudflare account') : undefined);
	return {
		async preflight(ctx) {
			const token = await ctx.store.get(KEY);
			if (!token) throw new Error(`${KEY} is not in the store`);
			const r = await locateCloudflareToken(token, await account(ctx));
			if (!r.ok) throw new Error(r.detail);
			return [r.detail];
		},
		async plan() {
			return [
				'verify the token at /user/tokens, else /accounts/{id}/tokens, for its id; then PUT …/tokens/{id}/value (roll in place)',
				'needs the token to carry "API Tokens: Edit" (user-owned) or "Account API Tokens: Edit" (account-owned); otherwise use a manual rotator',
				'nothing to revoke: the old value stops working the moment the roll returns',
			];
		},
		async provision(ctx): Promise<Provisioned> {
			const token = await ctx.store.get(KEY);
			if (!token) throw new Error(`${KEY} is not in the store`);
			const where = await locateCloudflareToken(token, await account(ctx));
			if (!where.ok || !where.id || !where.base) throw new Error(where.detail);
			try {
				const rolled = await http<{ result: string }>(`${where.base}/${where.id}/value`, {
					method: 'PUT',
					headers: { ...bearer(token), 'content-type': 'application/json' },
					body: '{}',
				});
				return { values: { [KEY]: rolled.result }, revoke: [], notes: [`rolled token ${where.id}`] };
			} catch (e) {
				if (e instanceof HttpError && (e.status === 403 || e.status === 401)) {
					const perm = where.account ? '"Account → Account API Tokens → Edit"' : '"User → API Tokens → Edit"';
					throw new Error(`token ${where.id} may not roll itself (HTTP ${e.status}); give it ${perm} or switch this secret to a manual rotator`);
				}
				throw e;
			}
		},
		async probe(values, ctx) {
			const v = values[KEY];
			return v ? locateCloudflareToken(v, await account(ctx)) : { ok: false, detail: `${KEY} missing` };
		},
	};
}
