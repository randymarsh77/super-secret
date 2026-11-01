import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Logger, SecretStore, Values } from '../types.ts';
import { redact, run } from '../util.ts';

/**
 * 1Password as the secret store, through the `op` CLI.
 *
 * One Secure Note per deployment target (`production`, `railway-staging`…)
 * in one vault. Two layouts:
 *
 *   sections (default)             flat
 *   current.<KEY>                  <KEY>
 *   previous.<KEY>                 <KEY>_previous
 *   meta.<KEY>_rotated_at          <KEY>_rotated_at
 *
 * A set() moves the live value into the previous slot before writing the
 * current one, so a rotation keeps one step of history on top of 1Password's
 * own item history. `op://<vault>/<item>/current/<KEY>` (sections) or
 * `op://<vault>/<item>/<KEY>` (flat) is the reference `op run`, `op inject`
 * and the render command resolve.
 *
 * Auth: a signed-in desktop app (set `account` when several accounts are
 * configured, or `op` stops to ask) or OP_SERVICE_ACCOUNT_TOKEN. Item
 * creation goes through a 0600 JSON template so values stay off argv; `op
 * item edit` only takes assignments on argv, which is accepted on a
 * single-user machine or an ephemeral CI runner.
 */
export type OpLayout = 'sections' | 'flat';

export const CURRENT = 'current';
export const PREVIOUS = 'previous';
export const META = 'meta';
const PREVIOUS_SUFFIX = '_previous';
const ROTATED_SUFFIX = '_rotated_at';

interface OpField {
	id: string;
	label?: string;
	type?: string;
	value?: string;
	section?: { id: string; label?: string };
}
export interface OpItem {
	id: string;
	title: string;
	fields?: OpField[];
}

/** section label → field label → value. Unsectioned fields land under ''. */
export function fieldsBySection(item: OpItem): Record<string, Values> {
	const out: Record<string, Values> = {};
	for (const f of item.fields ?? []) {
		if (!f.label || f.value === undefined || f.value === '') continue;
		(out[f.section?.label ?? f.section?.id ?? ''] ??= {})[f.label] = f.value;
	}
	return out;
}

/** The three slots of a key as (section, label) pairs for a layout. */
export function slots(layout: OpLayout, key: string) {
	return layout === 'sections'
		? { current: [CURRENT, key], previous: [PREVIOUS, key], rotatedAt: [META, `${key}${ROTATED_SUFFIX}`] }
		: { current: ['', key], previous: ['', `${key}${PREVIOUS_SUFFIX}`], rotatedAt: ['', `${key}${ROTATED_SUFFIX}`] };
}

function read(existing: Record<string, Values>, [section, label]: readonly string[]): string | undefined {
	return existing[section!]?.[label!];
}

function spec([section, label]: readonly string[], type: 'password' | 'text'): string {
	return `${section ? `${section}.` : ''}${label}[${type}]`;
}

export interface Assignment {
	arg: string;
	key: string;
	movedToPrevious: boolean;
}

/**
 * `op item edit` assignments for new values. A key whose current value differs
 * gets its old value copied to the previous slot first, with a timestamp.
 * Values may contain '=', ':' or '/': only the first '=' after the field
 * spec separates name from value.
 */
export function planAssignments(
	existing: Record<string, Values>,
	values: Values,
	layout: OpLayout = 'sections',
	now = new Date()
): Assignment[] {
	const out: Assignment[] = [];
	for (const [key, value] of Object.entries(values)) {
		const s = slots(layout, key);
		const current = read(existing, s.current);
		const moved = current !== undefined && current !== value;
		if (moved) {
			out.push({ arg: `${spec(s.previous, 'password')}=${current}`, key, movedToPrevious: true });
			out.push({ arg: `${spec(s.rotatedAt, 'text')}=${now.toISOString()}`, key, movedToPrevious: true });
		}
		out.push({ arg: `${spec(s.current, 'password')}=${value}`, key, movedToPrevious: moved });
	}
	return out;
}

/** The JSON template `op item create --template` takes, for a brand-new item. */
export function createTemplate(title: string, values: Values, layout: OpLayout, now = new Date()) {
	const fields: Array<Record<string, unknown>> = [];
	const sections = new Set<string>();
	for (const [key, value] of Object.entries(values)) {
		const s = slots(layout, key);
		const [section, label] = s.current;
		if (section) sections.add(section);
		fields.push({
			id: section ? `${section}_${label}` : label,
			type: 'CONCEALED',
			label,
			value,
			...(section ? { section: { id: section } } : {}),
		});
		const [metaSection, metaLabel] = s.rotatedAt;
		if (metaSection) sections.add(metaSection);
		fields.push({
			id: metaSection ? `${metaSection}_${metaLabel}` : metaLabel,
			type: 'STRING',
			label: metaLabel,
			value: now.toISOString(),
			...(metaSection ? { section: { id: metaSection } } : {}),
		});
	}
	return {
		title,
		category: 'SECURE_NOTE',
		sections: [...sections].map((id) => ({ id, label: id })),
		fields,
	};
}

export function opAuthHint(account?: string): string | undefined {
	const env = process.env;
	if (env.OP_SERVICE_ACCOUNT_TOKEN) return undefined;
	if (!account && !env.OP_ACCOUNT)
		return 'no account configured: with several 1Password accounts signed in, `op` stops to ask which one (set store.account or OP_ACCOUNT)';
	return undefined;
}

export interface OnePasswordStoreOptions {
	vault: string;
	item: string;
	account?: string;
	layout?: OpLayout;
	apply: boolean;
	log: Logger;
	/** Injected for tests. */
	runner?: typeof run;
}

export class OnePasswordStore implements SecretStore {
	readonly label: string;
	readonly vault: string;
	readonly item: string;
	readonly layout: OpLayout;
	private readonly account?: string;
	private readonly apply: boolean;
	private readonly log: Logger;
	private readonly runner: typeof run;
	/** undefined = not loaded, null = item does not exist yet */
	private cache: Record<string, Values> | null | undefined;
	private warned = false;

	constructor(opts: OnePasswordStoreOptions) {
		this.vault = opts.vault;
		this.item = opts.item;
		this.account = opts.account;
		this.layout = opts.layout ?? 'sections';
		this.apply = opts.apply;
		this.log = opts.log;
		this.runner = opts.runner ?? run;
		this.label = `1Password op://${this.vault}/${this.item}`;
	}

	/** The `op://` reference for a key's current value. */
	reference(key: string): string {
		return this.layout === 'sections'
			? `op://${this.vault}/${this.item}/${CURRENT}/${key}`
			: `op://${this.vault}/${this.item}/${key}`;
	}

	private async op(args: string[], allowFail = false) {
		if (!this.warned) {
			const hint = opAuthHint(this.account);
			if (hint) this.log.warn(hint);
			this.warned = true;
		}
		const scope = ['--vault', this.vault, ...(this.account ? ['--account', this.account] : [])];
		return this.runner(['op', ...args, ...scope], { allowFail });
	}

	private async load(): Promise<Record<string, Values> | null> {
		if (this.cache !== undefined) return this.cache;
		const res = await this.op(['item', 'get', this.item, '--format', 'json', '--reveal'], true);
		if (res.code !== 0) {
			if (/isn't an item|not found|could not find|no item|more than one item/i.test(res.stderr)) {
				if (/more than one item/i.test(res.stderr))
					throw new Error(`op: several items are titled "${this.item}" in vault ${this.vault}; rename or delete one`);
				this.cache = null;
				return null;
			}
			throw new Error(`op item get "${this.item}" failed: ${res.stderr.trim()}`);
		}
		this.cache = fieldsBySection(JSON.parse(res.stdout) as OpItem);
		return this.cache;
	}

	async exists(): Promise<boolean> {
		return (await this.load()) !== null;
	}

	async get(key: string): Promise<string | undefined> {
		const s = await this.load();
		return s ? read(s, slots(this.layout, key).current) : undefined;
	}

	async getAll(): Promise<Values> {
		const s = await this.load();
		if (!s) return {};
		if (this.layout === 'sections') return { ...(s[CURRENT] ?? {}) };
		const out: Values = {};
		for (const [k, v] of Object.entries(s[''] ?? {})) {
			if (k.endsWith(PREVIOUS_SUFFIX) || k.endsWith(ROTATED_SUFFIX) || k === 'notesPlain') continue;
			out[k] = v;
		}
		return out;
	}

	async getPrevious(key: string): Promise<string | undefined> {
		const s = await this.load();
		return s ? read(s, slots(this.layout, key).previous) : undefined;
	}

	async getRotatedAt(key: string): Promise<string | undefined> {
		const s = await this.load();
		return s ? read(s, slots(this.layout, key).rotatedAt) : undefined;
	}

	async set(values: Values): Promise<void> {
		if (Object.keys(values).length === 0) return;
		const existing = (await this.load()) ?? {};
		const plan = planAssignments(existing, values, this.layout);
		for (const [k, v] of Object.entries(values)) {
			const moved = plan.some((a) => a.key === k && a.movedToPrevious);
			const was = read(existing, slots(this.layout, k).current);
			this.log.note(`${this.label}: ${k} ← ${redact(v)}${moved ? ` (previous ← ${redact(was)})` : ''}`);
		}
		if (!this.apply) return;
		if (this.cache === null) {
			// a new item: values ride in a 0600 template file, never on argv
			const dir = mkdtempSync(join(tmpdir(), 'super-secret-'));
			const file = join(dir, 'item.json');
			try {
				writeFileSync(file, JSON.stringify(createTemplate(this.item, values, this.layout)), { mode: 0o600 });
				await this.op(['item', 'create', '--template', file]);
			} finally {
				rmSync(dir, { recursive: true, force: true });
			}
		} else {
			await this.op(['item', 'edit', this.item, ...plan.map((a) => a.arg)]);
		}
		this.cache = undefined;
	}

	async clearPrevious(keys: string[]): Promise<void> {
		const existing = await this.load();
		if (!existing) return;
		const args: string[] = [];
		for (const key of keys) {
			const s = slots(this.layout, key);
			if (read(existing, s.previous) !== undefined) {
				const [section, label] = s.previous;
				args.push(`${section ? `${section}.` : ''}${label}[delete]`);
			}
		}
		if (!args.length) return;
		this.log.note(`${this.label}: clear previous slot of ${keys.join(', ')}`);
		if (!this.apply) return;
		await this.op(['item', 'edit', this.item, ...args]);
		this.cache = undefined;
	}
}
