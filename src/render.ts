import { mkdtempSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import type { Values } from './types.ts';
import { run } from './util.ts';

/**
 * Render a template of `KEY=op://vault/item/field` references into a file a
 * host, a pod or a container runtime takes as its environment. Non-reference
 * lines pass through as literals, so the rendered file is a complete
 * environment. A KEY ending in `_B64` is base64-encoded after reading (a
 * multi-line value such as an SSH key in one variable).
 */
export const REFERENCE_PREFIX = 'op://';
export const B64_SUFFIX = '_B64';

export interface TemplateEntry {
	key: string;
	source: string;
	line: number;
}

export function parseTemplate(text: string, name = 'template'): TemplateEntry[] {
	const entries: TemplateEntry[] = [];
	text.split('\n').forEach((raw, i) => {
		const line = raw.trim();
		if (!line || line.startsWith('#')) return;
		const eq = line.indexOf('=');
		if (eq < 0) throw new Error(`${name}:${i + 1}: expected KEY=value`);
		const key = line.slice(0, eq).trim();
		if (!/^[A-Z_][A-Z0-9_]*$/.test(key)) throw new Error(`${name}:${i + 1}: "${key}" is not an upper-case variable name`);
		entries.push({ key, source: line.slice(eq + 1).trim(), line: i + 1 });
	});
	return entries;
}

export type Reader = (reference: string) => Promise<Buffer>;

export function opReader(account?: string): Reader {
	return async (reference) => {
		const res = await run(['op', 'read', '-n', reference, ...(account ? ['--account', account] : [])], { allowFail: true });
		if (res.code !== 0) throw new Error(res.stderr.trim() || `op read failed for ${reference}`);
		return Buffer.from(res.stdout, 'utf8');
	};
}

export function encode(key: string, raw: Buffer): string {
	if (key.endsWith(B64_SUFFIX)) {
		const bytes = raw.at(-1) === 0x0a ? raw : Buffer.concat([raw, Buffer.from('\n')]);
		return bytes.toString('base64');
	}
	const value = raw.toString('utf8');
	if (/[\r\n]/.test(value)) throw new Error(`${key}: value spans several lines; name it ${key}${B64_SUFFIX} to base64-encode it`);
	return value;
}

/** Resolve every entry. Errors name the KEY, never the value. */
export async function render(entries: TemplateEntry[], read: Reader): Promise<Values> {
	const values: Values = {};
	for (const { key, source } of entries) {
		let raw: Buffer;
		if (source.startsWith(REFERENCE_PREFIX)) {
			try {
				raw = await read(source);
			} catch (e) {
				throw new Error(`${key}: ${(e as Error).message}`);
			}
		} else raw = Buffer.from(source, 'utf8');
		const value = encode(key, raw);
		if (!value) throw new Error(`${key}: resolved to an empty value`);
		values[key] = value;
	}
	return values;
}

export const formatEnv = (values: Values): string => Object.entries(values).map(([k, v]) => `${k}=${v}\n`).join('');
export const formatJson = (values: Values): string => JSON.stringify(values, null, 2) + '\n';

/** Create `path` with mode 0600 atomically. */
export function writePrivate(path: string, content: string): void {
	const target = resolve(path);
	const dir = mkdtempSync(resolve(dirname(target), '.super-secret-'));
	const tmp = resolve(dir, 'out');
	try {
		writeFileSync(tmp, content, { mode: 0o600 });
		renameSync(tmp, target);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
}
