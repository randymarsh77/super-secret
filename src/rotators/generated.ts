import type { Ctx, Provisioned, Rotator, SecretDef, Values } from '../types.ts';
import { type Alphabet, randomSecret } from '../util.ts';
import { type ProbeSpec, runProbe } from './probes.ts';

export interface GeneratedSpec {
	kind: 'generated';
	length?: number;
	alphabet?: Alphabet;
	/** Keys to regenerate (default: all of the secret's keys). */
	keys?: string[];
	/** How to check the new value once deployed (default: none). */
	probe?: ProbeSpec;
}

/** A random value the project itself verifies: shared bearer tokens, session signing keys, admin passwords. */
export function generatedRotator(spec: GeneratedSpec = { kind: 'generated' }): Rotator {
	const keysOf = (def: SecretDef) => spec.keys ?? def.keys;
	return {
		async preflight(ctx, def) {
			const missing: string[] = [];
			for (const k of keysOf(def)) if ((await ctx.store.get(k)) === undefined) missing.push(k);
			return [missing.length ? `${missing.join(', ')} not in the store yet (first rotation sets it)` : 'current value in the store'];
		},
		async plan(_ctx, def) {
			return [
				`generate ${keysOf(def).join(', ')}: ${spec.length ?? 32} chars, ${spec.alphabet ?? 'alnum'}`,
				'nothing to retire at a provider: the old value stops working when every consumer carries the new one',
			];
		},
		async provision(_ctx, def): Promise<Provisioned> {
			const values: Values = {};
			for (const k of keysOf(def)) values[k] = randomSecret(spec.length ?? 32, spec.alphabet ?? 'alnum');
			return { values, revoke: [] };
		},
		probe(values, ctx, def) {
			return runProbe(spec.probe, values, ctx, def);
		},
	};
}
