#!/usr/bin/env node
/**
 * super-secret — import, push and rotate a project's secrets with 1Password as
 * the store. Dry run is the default; nothing is written without --apply.
 *
 *   super-secret status [--probe]                      what is where (store vs each target), pending revocations
 *   super-secret init                                  write a starter super-secret.json
 *   super-secret import [ids|KEYS…] [--from env:.env] [--apply]
 *                                                      copy values from an env file into the store
 *   super-secret import --paste KEY… [--apply]         paste values (hidden) into the store
 *   super-secret import --operator NAME… [--apply]     copy operator credentials from the shell env into the operator item
 *   super-secret pull <target> [ids…] [--apply]        copy a readable target's values into the store (one-time sync)
 *   super-secret push [ids…] [--targets a,b] [--no-deploy] [--force] [--apply]
 *                                                      deploy the store's values to the targets, redeploy what changed
 *   super-secret plan [ids…]                           dry run of rotate
 *   super-secret rotate [ids…] --apply [--targets a,b] [--no-deploy] [--no-revoke] [--skip-manual]
 *   super-secret verify [ids…] [--previous] [--expect-dead]
 *   super-secret revoke-pending [--apply] [--ack-manual]
 *   super-secret deploy <target>… --apply
 *   super-secret render --template FILE (--check | --out FILE [--format env|json])
 *
 * --manifest PATH picks the manifest (default: super-secret.config.{ts,mts,mjs,js} or super-secret.json in the cwd).
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { createStore, findManifest, loadManifest, resolveManifest, selectSecrets } from './manifest.ts';
import { makeOperatorEnv, operatorStore } from './operator.ts';
import { deployTargets, importStore, pullFromTarget, push, revokePending, rotate, status, verify } from './pipeline.ts';
import { formatEnv, formatJson, opReader, parseTemplate, render, writePrivate } from './render.ts';
import { EnvFileStore, memoryStore } from './store/index.ts';
import type { Ctx, SecretDef, Values } from './types.ts';
import { makeLogger, readHidden } from './util.ts';

const { values: flags, positionals } = parseArgs({
	args: process.argv.slice(2),
	allowPositionals: true,
	strict: true,
	options: {
		manifest: { type: 'string' },
		apply: { type: 'boolean', default: false },
		from: { type: 'string' },
		paste: { type: 'boolean', default: false },
		operator: { type: 'boolean', default: false },
		targets: { type: 'string' },
		'no-deploy': { type: 'boolean', default: false },
		'no-revoke': { type: 'boolean', default: false },
		'skip-manual': { type: 'boolean', default: false },
		'ack-manual': { type: 'boolean', default: false },
		'expect-dead': { type: 'boolean', default: false },
		previous: { type: 'boolean', default: false },
		probe: { type: 'boolean', default: false },
		force: { type: 'boolean', default: false },
		template: { type: 'string' },
		out: { type: 'string' },
		format: { type: 'string', default: 'env' },
		check: { type: 'boolean', default: false },
		help: { type: 'boolean', short: 'h', default: false },
	},
});

const [command = 'status', ...rest] = positionals;

function usage(): void {
	const src = readFileSync(new URL(import.meta.url), 'utf8');
	const header = src.split('*/')[0]!.split('\n').slice(2).map((l) => l.replace(/^ \* ?/, ''));
	console.log(header.join('\n').trim());
}

if (flags.help || command === 'help') {
	usage();
	process.exit(0);
}

if (command === 'init') {
	const file = resolve(process.cwd(), 'super-secret.json');
	if (existsSync(file)) {
		console.error(`${file} already exists`);
		process.exit(1);
	}
	writeFileSync(
		file,
		JSON.stringify(
			{
				$schema: 'https://github.com/randymarsh77/super-secret#manifest',
				store: { kind: 'op', vault: 'my-vault', item: 'production', account: 'my.1password.com' },
				targets: {
					github: { kind: 'github', repo: 'owner/repo' },
				},
				secrets: [
					{
						id: 'example-token',
						description: 'Replace me: a shared bearer token the app verifies itself',
						keys: ['EXAMPLE_TOKEN'],
						targets: { github: true },
						rotator: { kind: 'generated', length: 48 },
					},
				],
			},
			null,
			2
		) + '\n'
	);
	console.log(`wrote ${file}; add .super-secret/ to .gitignore`);
	process.exit(0);
}

// A TypeScript manifest on a Node that does not strip types by default (22.x):
// re-run ourselves with the flag so `import()` of the .ts file works.
{
	const path = flags.manifest ? resolve(process.cwd(), flags.manifest) : findManifest();
	const isTs = !!path && /\.(mts|ts)$/.test(path);
	const features = (process as unknown as { features: Record<string, unknown> }).features;
	if (isTs && !features.typescript && !process.execArgv.includes('--experimental-strip-types')) {
		const r = spawnSync(process.execPath, ['--experimental-strip-types', '--no-warnings', ...process.argv.slice(1)], { stdio: 'inherit' });
		process.exit(r.status ?? 1);
	}
}

const apply = flags.apply && command !== 'plan';
const log = makeLogger(!apply);
const onlyTargets = flags.targets?.split(',').map((s) => s.trim()).filter(Boolean);

function splitIdsAndKeys(tokens: string[], defs: SecretDef[]): { ids: string[]; keys: string[] } {
	const ids: string[] = [];
	const keys: string[] = [];
	for (const t of tokens) (/^[A-Z][A-Z0-9_]*$/.test(t) ? keys : ids).push(t);
	const selected = selectSecrets(defs, ids);
	const known = new Set(defs.flatMap((d) => d.keys));
	const unknownKeys = keys.filter((k) => !known.has(k));
	if (unknownKeys.length) throw new Error(`key(s) not in the manifest: ${unknownKeys.join(', ')}`);
	return { ids, keys: keys.length ? keys : selected.flatMap((d) => d.keys) };
}

try {
	if (command === 'render') {
		if (!flags.template) throw new Error('render needs --template FILE');
		if (!flags.check && !flags.out) throw new Error('render needs --check or --out FILE');
		const manifest = await loadManifest(flags.manifest).catch(() => undefined);
		const account = manifest?.config.store.kind === 'op' ? manifest.config.store.account : undefined;
		const entries = parseTemplate(readFileSync(resolve(process.cwd(), flags.template), 'utf8'), flags.template);
		const values = await render(entries, opReader(account));
		for (const e of entries)
			console.log(`   ${e.key.padEnd(28)} ok  ${e.source.startsWith('op://') ? 'reference' : 'literal'}${e.key.endsWith('_B64') ? ' (base64)' : ''}`);
		if (flags.check) console.log(`== ${entries.length} keys resolve from ${flags.template}`);
		else {
			writePrivate(flags.out!, flags.format === 'json' ? formatJson(values) : formatEnv(values));
			console.log(`== wrote ${entries.length} keys to ${flags.out} (mode 0600); delete it when it has been consumed`);
		}
		process.exit(0);
	}

	const manifest = await loadManifest(flags.manifest);
	const { targets, secrets } = resolveManifest(manifest.config);
	const store = createStore(manifest.config.store, apply, log, manifest.root);
	const operator = makeOperatorEnv(manifest.config.store, manifest.config.operator, log);
	const ctx: Ctx = {
		store,
		apply,
		log,
		operator,
		targets,
		root: manifest.root,
		stateDir: resolve(manifest.root, manifest.config.stateDir ?? '.super-secret'),
	};
	const dryRunHint = (verb: string) => {
		if (!apply) log.info(`\nDry run. Re-run with --apply to ${verb}.`);
	};

	switch (command) {
		case 'status':
			await status(selectSecrets(secrets, rest), ctx, { probe: flags.probe });
			break;
		case 'plan':
		case 'rotate':
			await rotate(selectSecrets(secrets, rest), ctx, {
				deploy: !flags['no-deploy'],
				revoke: !flags['no-revoke'],
				targets: onlyTargets,
				skipManual: flags['skip-manual'],
			});
			if (!apply) log.info('\nDry run. Re-run `rotate … --apply` to execute.');
			break;
		case 'import': {
			if (flags.operator) {
				const names = rest;
				if (!names.length) throw new Error('import --operator needs the variable names to copy');
				const present: Values = {};
				for (const n of names) {
					const v = process.env[n] ?? (flags.paste ? await readHidden(`Paste ${n} (hidden): `) : undefined);
					if (v) present[n] = v;
					else log.note(`${n}: not in the shell env, skipped (use --paste to enter it)`);
				}
				const to = operatorStore(manifest.config.store, manifest.config.operator, apply, log);
				await importStore(memoryStore(present, 'shell env'), to, names, ctx);
				dryRunHint('write the operator item');
				break;
			}
			const { keys } = splitIdsAndKeys(rest, secrets);
			if (flags.paste) {
				const pasted: Values = {};
				for (const k of keys) {
					const v = await readHidden(`Paste ${k} (hidden, empty to skip): `);
					if (v) pasted[k] = v;
				}
				await importStore(memoryStore(pasted, 'pasted values'), store, Object.keys(pasted), ctx);
			} else {
				const spec = flags.from ?? 'env:.env';
				const [kind, arg] = spec.includes(':') ? [spec.slice(0, spec.indexOf(':')), spec.slice(spec.indexOf(':') + 1)] : [spec, ''];
				if (kind !== 'env') throw new Error(`--from must be env:<file> (for a target, use \`pull <target>\`)`);
				const from = new EnvFileStore(resolve(manifest.root, arg || '.env'), false, log);
				await importStore(from, store, keys, ctx);
			}
			dryRunHint('write the store');
			break;
		}
		case 'pull': {
			const [target, ...ids] = rest;
			if (!target) throw new Error('pull needs a target name');
			await pullFromTarget(selectSecrets(secrets, ids), target, ctx);
			dryRunHint('write the store');
			break;
		}
		case 'push':
			await push(selectSecrets(secrets, rest), ctx, { deploy: !flags['no-deploy'], targets: onlyTargets, force: flags.force });
			dryRunHint('push');
			break;
		case 'verify': {
			const ok = await verify(selectSecrets(secrets, rest), ctx, flags['expect-dead'], flags.previous ? 'previous' : 'current');
			process.exit(ok ? 0 : 1);
		}
		// eslint-disable-next-line no-fallthrough
		case 'revoke-pending':
			await revokePending(secrets, ctx, { ackManual: flags['ack-manual'] });
			dryRunHint('revoke');
			break;
		case 'deploy':
			if (!rest.length) throw new Error('deploy needs target name(s)');
			await deployTargets(ctx, rest);
			dryRunHint('deploy');
			break;
		default:
			console.error(`Unknown command "${command}".\n`);
			usage();
			process.exit(2);
	}
} catch (e) {
	console.error(`\n✗ ${(e as Error).message}`);
	process.exit(1);
}
