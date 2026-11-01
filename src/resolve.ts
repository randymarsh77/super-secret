import type { Ctx } from './types.ts';

const REF = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;

/**
 * Config strings may name a store key or operator variable as `${KEY}`
 * (a Railway project id kept in the vault, a token in the operator item).
 * Anything else is a literal.
 */
export async function resolveRef(value: string, ctx: Ctx, what: string): Promise<string> {
	const m = REF.exec(value.trim());
	if (!m) return value;
	const key = m[1]!;
	const v = (await ctx.store.get(key)) ?? (await ctx.operator.get(key));
	if (v === undefined) throw new Error(`${what}: \${${key}} is neither in ${ctx.store.label} nor in the operator env`);
	return v;
}
