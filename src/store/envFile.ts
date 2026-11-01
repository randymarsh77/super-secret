import { chmodSync, copyFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import type { Logger, SecretStore, Values } from '../types.ts';
import { redact } from '../util.ts';

const LINE = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;

export function parseEnv(text: string): Values {
	const out: Values = {};
	for (const raw of text.split('\n')) {
		const m = LINE.exec(raw.trim());
		if (!m || m[1]! in out) continue;
		out[m[1]!] = unquote(m[2]!);
	}
	return out;
}

function unquote(v: string): string {
	const t = v.trim();
	if (t.length >= 2 && ((t[0] === '"' && t.at(-1) === '"') || (t[0] === "'" && t.at(-1) === "'")))
		return t.slice(1, -1);
	return t;
}

function quote(v: string): string {
	return /[\s#"'\\]/.test(v) ? JSON.stringify(v) : v;
}

/**
 * Replace the first active `KEY=` line for each key, append the rest in a
 * managed block at the end. Comments and ordering are preserved. Commented-out
 * alternates (`# KEY=...`) are left alone.
 */
export function upsertEnv(text: string, values: Values): string {
	const lines = text.split('\n');
	const pending = new Map(Object.entries(values));
	for (let i = 0; i < lines.length; i++) {
		const m = LINE.exec(lines[i]!.trim());
		if (m && pending.has(m[1]!)) {
			lines[i] = `${m[1]}=${quote(pending.get(m[1]!)!)}`;
			pending.delete(m[1]!);
		}
	}
	if (pending.size > 0) {
		if (lines.at(-1) !== '') lines.push('');
		lines.push('# Managed by super-secret');
		for (const [k, v] of pending) lines.push(`${k}=${quote(v)}`);
		lines.push('');
	}
	return lines.join('\n');
}

/** A git-ignored env file as the store. Writes keep a timestamped 0600 backup beside the file. */
export class EnvFileStore implements SecretStore {
	readonly label: string;
	readonly path: string;
	private readonly apply: boolean;
	private readonly log: Logger;
	private readonly backup: boolean;

	constructor(path: string, apply: boolean, log: Logger, backup = true) {
		this.path = path;
		this.apply = apply;
		this.log = log;
		this.backup = backup;
		this.label = `env file ${path}`;
	}

	private read(): string {
		return existsSync(this.path) ? readFileSync(this.path, 'utf8') : '';
	}

	async get(key: string): Promise<string | undefined> {
		return parseEnv(this.read())[key];
	}

	async getAll(): Promise<Values> {
		return parseEnv(this.read());
	}

	async set(values: Values): Promise<void> {
		for (const [k, v] of Object.entries(values)) this.log.note(`${this.label}: ${k} ← ${redact(v)}`);
		if (!this.apply) return;
		const current = this.read();
		if (current && this.backup) {
			const backup = `${this.path}.bak.${Date.now()}`;
			copyFileSync(this.path, backup);
			chmodSync(backup, 0o600);
			this.log.note(`backup written to ${backup}`);
		}
		writeFileSync(this.path, upsertEnv(current, values), { mode: 0o600 });
	}
}
