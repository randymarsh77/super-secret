import type { Ctx, Provisioned, Rotator, SecretDef, Values } from '../types.ts';
import { readHidden } from '../util.ts';
import { type ProbeSpec, runProbe } from './probes.ts';

export interface ManualSpec {
	kind: 'manual';
	/** Where the new value is minted. Shown before the paste prompt. */
	create: string;
	/** How the old value is retired. Queued as a manual revocation. */
	retire?: string;
	/** Keys to prompt for, in order (default: all of the secret's keys). */
	keys?: string[];
	/** Regex each pasted value must match, per key or for all. */
	pattern?: string | Record<string, string>;
	probe?: ProbeSpec;
}

/**
 * The provider has no API for minting this credential: the operator creates
 * it in a dashboard and pastes it (hidden, or piped on stdin). It is
 * pattern-checked and probed before it is accepted.
 */
export function manualRotator(spec: ManualSpec): Rotator {
	const keysOf = (def: SecretDef) => spec.keys ?? def.keys;
	const patternFor = (key: string) =>
		typeof spec.pattern === 'string' ? spec.pattern : spec.pattern?.[key];
	return {
		manual: true,
		async preflight(ctx, def) {
			const current: Values = {};
			for (const k of def.keys) {
				const v = await ctx.store.get(k);
				if (v !== undefined) current[k] = v;
			}
			if (!Object.keys(current).length) return ['nothing in the store yet'];
			if (!spec.probe || spec.probe.kind === 'none') return ['current value in the store (no probe)'];
			const r = await runProbe(spec.probe, current, ctx, def);
			if (!r.ok) throw new Error(`current value failed its probe: ${r.detail}`);
			return [`current value works: ${r.detail}`];
		},
		async plan(_ctx, def) {
			return [
				`MANUAL: ${spec.create}`,
				`paste ${keysOf(def).join(', then ')} when prompted (hidden); checked${spec.probe && spec.probe.kind !== 'none' ? ' and probed' : ''} before it is stored`,
				...(spec.retire ? [`old value: ${spec.retire} (queued as a manual revoke)`] : ['old value: nothing to retire']),
			];
		},
		async provision(ctx, def): Promise<Provisioned> {
			ctx.log.info(`create the new value: ${spec.create}`);
			const values: Values = {};
			for (const key of keysOf(def)) {
				const value = await readHidden(`Paste the new ${key} (hidden): `);
				if (!value) throw new Error(`${key}: empty value, nothing changed`);
				const pattern = patternFor(key);
				if (pattern && !new RegExp(pattern).test(value)) throw new Error(`${key}: does not match ${pattern}`);
				if (value === (await ctx.store.get(key))) throw new Error(`${key}: that is the current value, not a new one`);
				values[key] = value;
			}
			const r = await runProbe(spec.probe, values, ctx, def);
			if (!r.ok) throw new Error(`new value failed its probe: ${r.detail}`);
			return {
				values,
				revoke: spec.retire ? [{ kind: 'manual', summary: spec.retire, instructions: spec.retire }] : [],
				notes: [r.detail],
			};
		},
		probe(values, ctx, def) {
			return runProbe(spec.probe, values, ctx, def);
		},
	};
}
