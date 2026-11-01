import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createRotator, type RotatorSpec } from './rotators/index.ts';
import { EnvFileStore, OnePasswordStore, type OpLayout } from './store/index.ts';
import { createTarget, type TargetConfig } from './targets/index.ts';
import type { Logger, Rotator, SecretDef, SecretStore, Target, TargetBinding } from './types.ts';

export type StoreConfig =
	| {
			kind: 'op';
			vault: string;
			/** One Secure Note per deployment target, e.g. `production`. */
			item: string;
			/** 1Password account (sign-in address or shorthand) when several are signed in. */
			account?: string;
			layout?: OpLayout;
	  }
	| {
			kind: 'env';
			/** Relative to the manifest. */
			file: string;
	  };

export interface OperatorConfig {
	/** 1Password item in the store's vault holding operator credentials (default `operator`). */
	item?: string;
	layout?: OpLayout;
}

export interface SecretConfig {
	id: string;
	description?: string;
	keys: string[];
	/** target name → true (same names) or {storeKey: targetKey}. */
	targets?: Record<string, TargetBinding>;
	rotator: RotatorSpec | Rotator;
	disruption?: string;
}

export interface ManifestConfig {
	store: StoreConfig;
	/** false: operator credentials come from the shell env only. */
	operator?: OperatorConfig | false;
	targets?: Record<string, TargetConfig | Target>;
	secrets: SecretConfig[];
	/** Pending revocations live here, relative to the root (default `.super-secret`). Git-ignore it. */
	stateDir?: string;
	/**
	 * The directory relative paths resolve against (targets' cwd and files,
	 * stateDir), relative to the manifest file. Default: the manifest's own
	 * directory; a manifest kept in `infra/` sets `root: '..'`.
	 */
	root?: string;
}

/** Identity helper so a TypeScript manifest gets completion and checking. */
export function defineManifest(config: ManifestConfig): ManifestConfig {
	return config;
}

export const MANIFEST_NAMES = [
	'super-secret.config.ts',
	'super-secret.config.mts',
	'super-secret.config.mjs',
	'super-secret.config.js',
	'super-secret.json',
];

export interface LoadedManifest {
	config: ManifestConfig;
	path: string;
	/** `config.root` resolved: relative paths resolve against it. */
	root: string;
}

export function findManifest(cwd = process.cwd()): string | undefined {
	for (const name of MANIFEST_NAMES) {
		const p = resolve(cwd, name);
		if (existsSync(p)) return p;
	}
	return undefined;
}

export async function loadManifest(path?: string, cwd = process.cwd()): Promise<LoadedManifest> {
	const file = path ? resolve(cwd, path) : findManifest(cwd);
	if (!file) throw new Error(`no manifest: pass --manifest, or create one of ${MANIFEST_NAMES.join(', ')} (super-secret init)`);
	if (!existsSync(file)) throw new Error(`manifest ${file} does not exist`);
	let config: ManifestConfig;
	if (file.endsWith('.json')) {
		config = JSON.parse(readFileSync(file, 'utf8')) as ManifestConfig;
	} else {
		const mod = (await import(pathToFileURL(file).href)) as { default?: ManifestConfig; manifest?: ManifestConfig };
		const found = mod.default ?? mod.manifest;
		if (!found) throw new Error(`${file}: export the manifest as default (defineManifest({...})) or as \`manifest\``);
		config = found;
	}
	const errors = validateManifest(config);
	if (errors.length) throw new Error(`${file}:\n  - ${errors.join('\n  - ')}`);
	return { config, path: file, root: resolve(dirname(file), config.root ?? '.') };
}

const KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;
const ID = /^[a-z0-9][a-z0-9-]*$/;

export function validateManifest(cfg: ManifestConfig): string[] {
	const errors: string[] = [];
	if (!cfg || typeof cfg !== 'object') return ['manifest must be an object'];
	const store = cfg.store as StoreConfig | undefined;
	if (!store) errors.push('store is required');
	else if (store.kind === 'op') {
		if (!store.vault) errors.push('store.vault is required');
		if (!store.item) errors.push('store.item is required');
		if (store.layout && !['sections', 'flat'].includes(store.layout)) errors.push(`store.layout must be sections or flat`);
	} else if (store.kind === 'env') {
		if (!store.file) errors.push('store.file is required');
	} else errors.push(`store.kind must be op or env`);
	if (cfg.root !== undefined && typeof cfg.root !== 'string') errors.push('root must be a path string');
	const targets = cfg.targets ?? {};
	for (const [name, t] of Object.entries(targets)) {
		if (!ID.test(name)) errors.push(`target "${name}": name must be [a-z0-9-]`);
		if (!t || typeof t !== 'object') errors.push(`target ${name}: must be an object`);
	}
	if (!Array.isArray(cfg.secrets) || !cfg.secrets.length) errors.push('secrets must be a non-empty array');
	const ids = new Set<string>();
	const keys = new Map<string, string>();
	for (const [i, s] of (cfg.secrets ?? []).entries()) {
		const at = `secrets[${i}]${s?.id ? ` (${s.id})` : ''}`;
		if (!s?.id || !ID.test(s.id)) errors.push(`${at}: id must be [a-z0-9-]`);
		else if (ids.has(s.id)) errors.push(`${at}: duplicate id`);
		else ids.add(s.id);
		if (!Array.isArray(s?.keys) || !s.keys.length) errors.push(`${at}: keys must be a non-empty array`);
		else
			for (const k of s.keys) {
				if (!KEY.test(k)) errors.push(`${at}: key "${k}" is not an env var name`);
				else if (keys.has(k)) errors.push(`${at}: key ${k} already belongs to ${keys.get(k)}`);
				else keys.set(k, s.id);
			}
		for (const [t, binding] of Object.entries(s?.targets ?? {})) {
			if (!(t in targets)) errors.push(`${at}: target "${t}" is not defined`);
			if (binding !== true && (typeof binding !== 'object' || binding === null)) errors.push(`${at}: targets.${t} must be true or a key map`);
			else if (binding !== true)
				for (const [from, to] of Object.entries(binding)) {
					if (!s.keys?.includes(from)) errors.push(`${at}: targets.${t} maps ${from}, which is not one of its keys`);
					if (!KEY.test(to)) errors.push(`${at}: targets.${t} maps to "${to}", not an env var name`);
				}
		}
		if (!s?.rotator || typeof s.rotator !== 'object') errors.push(`${at}: rotator is required`);
		else if ('kind' in s.rotator) {
			const r = s.rotator;
			if (r.kind === 'manual' && !r.create) errors.push(`${at}: manual rotator needs \`create\` (where the value is minted)`);
			if (r.kind === 'stripe-webhook-secret' && !r.url) errors.push(`${at}: stripe-webhook-secret needs \`url\``);
		}
	}
	return errors;
}

export function createStore(cfg: StoreConfig, apply: boolean, log: Logger, root: string): SecretStore {
	if (cfg.kind === 'op')
		return new OnePasswordStore({ vault: cfg.vault, item: cfg.item, account: cfg.account, layout: cfg.layout, apply, log });
	return new EnvFileStore(resolve(root, cfg.file), apply, log);
}

export interface Resolved {
	targets: Record<string, Target>;
	secrets: SecretDef[];
}

export function resolveManifest(cfg: ManifestConfig): Resolved {
	const targets: Record<string, Target> = {};
	for (const [name, t] of Object.entries(cfg.targets ?? {})) targets[name] = createTarget(name, t);
	const secrets = cfg.secrets.map(
		(s): SecretDef => ({
			id: s.id,
			description: s.description,
			keys: s.keys,
			targets: s.targets ?? {},
			rotator: createRotator(s.rotator, s.id),
			disruption: s.disruption,
		})
	);
	return { targets, secrets };
}

export function selectSecrets(defs: SecretDef[], ids: string[]): SecretDef[] {
	if (ids.length === 0) return defs;
	const unknown = ids.filter((id) => !defs.some((d) => d.id === id));
	if (unknown.length) throw new Error(`unknown secret id(s): ${unknown.join(', ')}. Known: ${defs.map((d) => d.id).join(', ')}`);
	return defs.filter((d) => ids.includes(d.id));
}
