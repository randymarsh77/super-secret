import { RevocationQueue, type PendingRevocation } from './state.ts';
import { boundKeys, type Ctx, type SecretDef, type SecretStore, type Target, type Values } from './types.ts';
import { redact, sha } from './util.ts';

export interface RotateOptions {
	deploy: boolean;
	revoke: boolean;
	/** Only these targets receive pushes (default: every bound target). */
	targets?: string[];
	/** Leave out rotators that need a human at a terminal (CI, or --skip-manual). */
	skipManual?: boolean;
}

function queue(ctx: Ctx): RevocationQueue {
	return new RevocationQueue(ctx.stateDir);
}

/** The targets a set of secrets is bound to, filtered by an optional allow-list. */
export function targetsFor(defs: SecretDef[], ctx: Ctx, only?: string[]): Record<string, Target> {
	const names = new Set(defs.flatMap((d) => Object.keys(d.targets)));
	const out: Record<string, Target> = {};
	for (const name of names) {
		if (only && !only.includes(name)) continue;
		const t = ctx.targets[name];
		if (!t) throw new Error(`target "${name}" is bound but not defined`);
		out[name] = t;
	}
	if (only) for (const o of only) if (!ctx.targets[o]) throw new Error(`unknown target "${o}" (have: ${Object.keys(ctx.targets).join(', ')})`);
	return out;
}

/** Manual rotators read a pasted key from a TTY; without one they cannot run. */
export function dropManual(defs: SecretDef[], ctx: Ctx, skipManual?: boolean): SecretDef[] {
	const skip = skipManual || !process.stdin.isTTY;
	const kept = defs.filter((d) => !(skip && d.rotator.manual));
	for (const d of defs) if (!kept.includes(d)) ctx.log.warn(`${d.id}: skipped, needs a terminal to paste the new value`);
	return kept;
}

/** Fail before touching anything if a provider or target session is missing. */
export async function preflight(defs: SecretDef[], ctx: Ctx, targets: Record<string, Target>): Promise<void> {
	ctx.log.info(`Store: ${ctx.store.label}`);
	const problems: string[] = [];
	for (const def of defs) {
		try {
			for (const line of await def.rotator.preflight(ctx, def)) ctx.log.note(`✓ ${def.id}: ${line}`);
		} catch (e) {
			problems.push(`${def.id}: ${(e as Error).message}`);
		}
	}
	for (const [name, t] of Object.entries(targets)) {
		try {
			ctx.log.note(`✓ ${name}: ${await t.preflight(ctx)}`);
		} catch (e) {
			problems.push(`${name}: ${(e as Error).message}`);
		}
	}
	if (problems.length) throw new Error(`Preflight failed:\n  - ${problems.join('\n  - ')}`);
}

/** Values for one secret as a target sees them (renamed per the binding), from the given values or the store. */
async function targetValues(def: SecretDef, target: string, source: Values | SecretStore): Promise<Values> {
	const out: Values = {};
	for (const [from, to] of Object.entries(boundKeys(def, target))) {
		const v = 'get' in source && typeof source.get === 'function' ? await (source as SecretStore).get(from) : (source as Values)[from];
		if (v !== undefined) out[to] = v;
	}
	return out;
}

/**
 * provision → store → push to targets (no deploy) for each secret, then one
 * deploy per changed target, then probe every new value, then revoke the old
 * credentials. In dry-run mode each step is described and nothing is written.
 */
export async function rotate(all: SecretDef[], ctx: Ctx, opts: RotateOptions): Promise<void> {
	const defs = dropManual(all, ctx, opts.skipManual).filter((d) => !d.rotator.static);
	for (const d of all) if (d.rotator.static && !defs.includes(d)) ctx.log.note(`${d.id}: static, not rotated`);
	if (defs.length === 0) throw new Error('Nothing to rotate');
	const targets = targetsFor(defs, ctx, opts.targets);
	await preflight(defs, ctx, targets);

	const q = queue(ctx);
	const queued: PendingRevocation[] = [];
	const written: Record<string, Values> = {};
	const touched = new Set<string>();

	for (const def of defs) {
		ctx.log.info(`\n━━ ${def.id}${def.description ? ` — ${def.description}` : ''}`);
		if (def.disruption) ctx.log.note(`disruption: ${def.disruption}`);
		if (!ctx.apply) {
			for (const line of await def.rotator.plan(ctx, def)) ctx.log.step(line);
			const placeholder = Object.fromEntries(def.keys.map((k) => [k, `<new ${k}>`]));
			await ctx.store.set(placeholder);
			for (const [name, t] of Object.entries(targets)) {
				const v = await targetValues(def, name, placeholder);
				if (Object.keys(v).length) {
					await t.set(v, ctx);
					touched.add(name);
				}
			}
			continue;
		}
		ctx.log.step('provision');
		const result = await def.rotator.provision(ctx, def);
		for (const n of result.notes ?? []) ctx.log.note(n);
		if (result.revoke.length) {
			queued.push(...q.add(def.id, result.revoke));
			for (const r of result.revoke) ctx.log.note(`queued: ${r.summary}`);
		}
		ctx.log.step('store');
		await ctx.store.set(result.values);
		written[def.id] = result.values;
		for (const [name, t] of Object.entries(targets)) {
			const v = await targetValues(def, name, result.values);
			if (Object.keys(v).length) {
				await t.set(v, ctx);
				touched.add(name);
			}
		}
	}

	ctx.log.info('\n━━ deploy');
	if (!opts.deploy) ctx.log.note('skipped (--no-deploy)');
	else {
		let any = false;
		for (const name of touched) {
			const t = targets[name]!;
			if (!t.deploy) continue;
			any = true;
			await t.deploy(ctx);
		}
		if (!any) ctx.log.note('no touched target needs a deploy step');
	}

	ctx.log.info('\n━━ probe new values');
	let failures = 0;
	for (const def of defs) {
		if (!ctx.apply) {
			ctx.log.step(`${def.id}: would probe the new ${def.keys.join(', ')}`);
			continue;
		}
		const result = await def.rotator.probe(written[def.id] ?? {}, ctx, def);
		ctx.log.step(`${def.id}: ${result.ok ? 'OK' : 'FAIL'} — ${result.detail}`);
		if (!result.ok) failures++;
	}
	if (failures)
		throw new Error(
			`${failures} probe(s) failed. Nothing has been revoked; the old credentials stay queued in ${ctx.stateDir}. Fix, then run \`revoke-pending --apply\`.`
		);

	ctx.log.info('\n━━ revoke old credentials');
	if (!ctx.apply) ctx.log.note('would revoke whatever each plan step above listed');
	else if (!opts.revoke) ctx.log.note('skipped (--no-revoke); run `revoke-pending --apply` later');
	else await revokePending(defs, ctx, { only: queued });
}

/** Retire queued credentials. Manual ones are printed and left in the queue until --ack-manual. */
export async function revokePending(
	defs: SecretDef[],
	ctx: Ctx,
	opts: { only?: PendingRevocation[]; ackManual?: boolean } = {}
): Promise<void> {
	const q = queue(ctx);
	const items = opts.only ?? q.list();
	if (items.length === 0) {
		ctx.log.info('No pending revocations.');
		return;
	}
	for (const item of items) {
		const d = item.descriptor;
		ctx.log.step(`[${item.secretId}] ${d.summary}`);
		if (d.kind === 'manual') {
			if (opts.ackManual && ctx.apply) {
				q.remove([item.id]);
				await ctx.store.clearPrevious?.(defs.find((x) => x.id === item.secretId)?.keys ?? []);
			} else ctx.log.note('left in the queue; re-run `revoke-pending --apply --ack-manual` once done');
			continue;
		}
		if (!ctx.apply) continue;
		const def = defs.find((x) => x.id === item.secretId);
		if (!def?.rotator.revoke) throw new Error(`${item.secretId}: no rotator can revoke kind "${d.kind}"`);
		await def.rotator.revoke(d, ctx, def);
		q.remove([item.id]);
		await ctx.store.clearPrevious?.(def.keys);
		ctx.log.note('revoked');
	}
}

/**
 * Probe what the store holds for each secret: the current values, or with
 * slot 'previous' the backup slot (expected dead after a rotation).
 */
export async function verify(defs: SecretDef[], ctx: Ctx, expectDead: boolean, slot: 'current' | 'previous' = 'current'): Promise<boolean> {
	if (slot === 'previous' && !ctx.store.getPrevious) throw new Error(`${ctx.store.label} keeps no previous slot`);
	let allGood = true;
	for (const def of defs) {
		if (def.rotator.static) continue;
		const values: Values = {};
		for (const k of def.keys) {
			const v = slot === 'previous' ? await ctx.store.getPrevious!(k) : await ctx.store.get(k);
			if (v !== undefined) values[k] = v;
		}
		if (Object.keys(values).length === 0) {
			ctx.log.step(`${def.id}: nothing in the ${slot} slot`);
			continue;
		}
		let result;
		try {
			result = await def.rotator.probe(values, ctx, def);
		} catch (e) {
			result = { ok: false, detail: (e as Error).message };
		}
		const good = expectDead ? !result.ok : result.ok;
		allGood &&= good;
		ctx.log.step(`${def.id}: ${good ? '✓' : '✗'} ${expectDead ? (result.ok ? 'STILL VALID' : 'dead') : result.ok ? 'valid' : 'INVALID'} — ${result.detail}`);
	}
	return allGood;
}

/** Copy keys from one store into another; equal values are skipped. */
export async function importStore(from: SecretStore, to: SecretStore, keys: string[], ctx: Ctx): Promise<void> {
	const values: Values = {};
	for (const key of keys) {
		const v = await from.get(key);
		if (v === undefined) {
			ctx.log.note(`${key}: not in ${from.label}, skipped`);
			continue;
		}
		if ((await to.get(key)) === v) ctx.log.note(`${key}: already equal`);
		else values[key] = v;
	}
	if (Object.keys(values).length === 0) {
		ctx.log.info(`${to.label} already matches ${from.label}.`);
		return;
	}
	ctx.log.step(`${from.label} → ${to.label}: ${Object.keys(values).join(', ')}`);
	await to.set(values);
}

/** One-time sync from a readable target (the platform is the source of truth until the first rotation). */
export async function pullFromTarget(defs: SecretDef[], targetName: string, ctx: Ctx): Promise<void> {
	const t = ctx.targets[targetName];
	if (!t) throw new Error(`unknown target "${targetName}"`);
	if (!t.readable) throw new Error(`${t.label} is write-only; its values cannot be read back`);
	const wanted = defs.filter((d) => d.targets[targetName]);
	const keys = wanted.flatMap((d) => Object.values(boundKeys(d, targetName)));
	const scopes = await t.read(keys, ctx);
	const values: Values = {};
	for (const def of wanted)
		for (const [from, to] of Object.entries(boundKeys(def, targetName))) {
			const seen = new Set(Object.values(scopes).map((s) => s[to]).filter((v): v is string => v !== undefined));
			if (seen.size === 0) ctx.log.note(`${from}: not set on ${t.label}, skipped`);
			else if (seen.size > 1) ctx.log.warn(`${from}: ${t.label} holds ${seen.size} different values across scopes; not pulled`);
			else values[from] = [...seen][0]!;
		}
	const changes: Values = {};
	for (const [k, v] of Object.entries(values)) {
		if ((await ctx.store.get(k)) === v) ctx.log.note(`${k}: already equal`);
		else changes[k] = v;
	}
	if (!Object.keys(changes).length) {
		ctx.log.info('Store already matches the target.');
		return;
	}
	ctx.log.step(`${t.label} → ${ctx.store.label}: ${Object.keys(changes).join(', ')}`);
	await ctx.store.set(changes);
}

/**
 * Deploy the store's values to where they are consumed: readable targets get
 * only the keys that differ; write-only targets get every bound key. Then one
 * deploy per target that changed.
 */
export async function push(defs: SecretDef[], ctx: Ctx, opts: { deploy: boolean; targets?: string[]; force?: boolean }): Promise<void> {
	const targets = targetsFor(defs, ctx, opts.targets);
	const changed = new Set<string>();
	for (const [name, t] of Object.entries(targets)) {
		const bound = defs.filter((d) => d.targets[name]);
		const wanted: Values = {};
		for (const def of bound) Object.assign(wanted, await targetValues(def, name, ctx.store));
		const missing = bound.flatMap((d) => Object.entries(boundKeys(d, name)).filter(([, to]) => !(to in wanted)).map(([from]) => from));
		for (const m of missing) ctx.log.note(`${name}: ${m} not in ${ctx.store.label}, skipped`);
		if (!Object.keys(wanted).length) continue;
		ctx.log.info(`\n━━ ${t.label}`);
		let toSet = wanted;
		if (t.readable && !opts.force) {
			const scopes = await t.read(Object.keys(wanted), ctx);
			toSet = {};
			for (const [k, v] of Object.entries(wanted)) {
				const differs = Object.values(scopes).some((s) => s[k] !== v);
				if (differs) toSet[k] = v;
				else ctx.log.note(`${k}: already equal`);
			}
		} else if (!t.readable) {
			const scopes = await t.read(Object.keys(wanted), ctx).catch(() => ({}));
			const present = new Set(Object.values(scopes).flatMap((s) => Object.keys(s)));
			for (const k of Object.keys(wanted)) ctx.log.note(`${k}: ${present.has(k) ? 'present (write-only, value unknown)' : 'MISSING'}`);
		}
		if (!Object.keys(toSet).length) continue;
		await t.set(toSet, ctx);
		changed.add(name);
	}
	ctx.log.info('\n━━ deploy');
	if (!changed.size) ctx.log.note('every target already matched the store; nothing to deploy');
	else if (!opts.deploy) ctx.log.note(`${[...changed].join(', ')} changed; deploy skipped (--no-deploy)`);
	else {
		let any = false;
		for (const name of changed) {
			const t = targets[name]!;
			if (!t.deploy) continue;
			any = true;
			await t.deploy(ctx);
		}
		if (!any) ctx.log.note('no changed target has a deploy step; values are live on write');
	}
}

export async function deployTargets(ctx: Ctx, names: string[]): Promise<void> {
	for (const name of names) {
		const t = ctx.targets[name];
		if (!t) throw new Error(`unknown target "${name}"`);
		if (!t.deploy) ctx.log.note(`${t.label}: no deploy step`);
		else await t.deploy(ctx);
	}
}

/** What is where, whether it still works, and what is waiting to be revoked. */
export async function status(defs: SecretDef[], ctx: Ctx, opts: { probe?: boolean } = {}): Promise<void> {
	const log = ctx.log;
	log.info(`Store:   ${ctx.store.label}`);
	for (const [name, t] of Object.entries(ctx.targets)) log.info(`Target:  ${name} = ${t.label}`);
	log.info('');
	const remote: Record<string, Record<string, Values> | Error> = {};
	for (const [name, t] of Object.entries(ctx.targets)) {
		const keys = [...new Set(defs.filter((d) => d.targets[name]).flatMap((d) => Object.values(boundKeys(d, name))))];
		if (!keys.length) continue;
		try {
			await t.preflight(ctx);
			remote[name] = await t.read(keys, ctx);
		} catch (e) {
			remote[name] = e as Error;
			log.warn(`${name}: ${(e as Error).message}`);
		}
	}
	for (const def of defs) {
		const tag = def.rotator.static ? '  (static)' : def.rotator.manual ? '  (manual provisioning)' : '';
		log.info(`${def.id}${tag}${def.description ? `  — ${def.description}` : ''}`);
		for (const key of def.keys) {
			const local = await ctx.store.get(key);
			const rotated = await ctx.store.getRotatedAt?.(key);
			const previous = await ctx.store.getPrevious?.(key);
			log.note(`${key.padEnd(30)} store ${redact(local)}${rotated ? `  rotated ${rotated}` : ''}${previous ? '  (previous slot held)' : ''}`);
			for (const [name, t] of Object.entries(ctx.targets)) {
				const to = boundKeys(def, name)[key];
				if (!to) continue;
				const r = remote[name];
				if (!r || r instanceof Error) {
					log.note(`${''.padEnd(30)} ${name}: ?`);
					continue;
				}
				for (const [scope, vals] of Object.entries(r)) {
					const v = vals[to];
					let state: string;
					if (v === undefined) state = local === undefined ? 'unset' : 'MISSING';
					else if (!t.readable) state = 'present';
					else if (local === undefined) state = `set (sha ${sha(v)}), store empty`;
					else state = v === local ? '= store' : `≠ store (sha ${sha(v)})`;
					log.note(`${''.padEnd(30)} ${name}/${scope}${to !== key ? ` as ${to}` : ''}: ${state}`);
				}
			}
		}
		if (opts.probe && !def.rotator.static) {
			try {
				for (const line of await def.rotator.preflight(ctx, def)) log.note(`✓ ${line}`);
			} catch (e) {
				log.note(`✗ ${(e as Error).message}`);
			}
		}
	}
	const pending = queue(ctx).list();
	log.info(`\nPending revocations: ${pending.length}`);
	for (const p of pending) log.note(`${p.createdAt} [${p.secretId}] ${p.descriptor.summary}`);
}
