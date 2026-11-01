import type { Rotator } from '../types.ts';

export interface StaticSpec {
	kind: 'static';
}

/** Never rotates: identifiers, usernames, public DSNs. Import and push only. */
export function staticRotator(): Rotator {
	return {
		static: true,
		async preflight(ctx, def) {
			const missing: string[] = [];
			for (const k of def.keys) if ((await ctx.store.get(k)) === undefined) missing.push(k);
			return [missing.length ? `${missing.join(', ')} not in the store` : 'in the store'];
		},
		async plan() {
			return ['static: not rotated'];
		},
		async provision(_ctx, def) {
			throw new Error(`${def.id} is static and cannot be rotated`);
		},
		async probe() {
			return { ok: true, detail: 'static value, nothing to probe' };
		},
	};
}
