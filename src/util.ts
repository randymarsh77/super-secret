import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import type { Logger, ProbeResult, Values } from './types.ts';

/** Show enough of a secret to recognise it, never enough to use it. */
export function redact(value: string | undefined): string {
	if (value === undefined) return '(unset)';
	if (value.length === 0) return '(empty)';
	const prefix = value.slice(0, Math.min(6, Math.floor(value.length / 4)));
	return `${prefix}…(${value.length} chars, sha ${sha(value)})`;
}

export function sha(value: string): string {
	return createHash('sha256').update(value).digest('hex').slice(0, 8);
}

export type Alphabet = 'alnum' | 'hex' | 'base64url';

const ALNUM = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';

/** A random secret. `alnum` needs no quoting or percent-encoding anywhere. */
export function randomSecret(length = 32, alphabet: Alphabet = 'alnum'): string {
	if (alphabet === 'hex') return randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
	if (alphabet === 'base64url') return randomBytes(Math.ceil((length * 3) / 4)).toString('base64url').slice(0, length);
	const bytes = randomBytes(length);
	let out = '';
	for (let i = 0; i < length; i++) out += ALNUM[bytes[i]! % ALNUM.length];
	return out;
}

export function stamp(date = new Date()): string {
	const p = (n: number) => String(n).padStart(2, '0');
	return `${date.getUTCFullYear()}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}_${p(date.getUTCHours())}${p(date.getUTCMinutes())}`;
}

export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

export class HttpError extends Error {
	readonly status: number;
	readonly url: string;
	readonly body: string;

	constructor(status: number, url: string, body: string) {
		super(`${status} from ${url}: ${body.slice(0, 300)}`);
		this.status = status;
		this.url = url;
		this.body = body;
	}
}

/** fetch() that throws HttpError on non-2xx and parses JSON. */
export async function http<T = unknown>(url: string, init: RequestInit = {}): Promise<T> {
	const res = await fetch(url, { ...init, signal: init.signal ?? AbortSignal.timeout(30_000) });
	const text = await res.text();
	if (!res.ok) throw new HttpError(res.status, url, text);
	return (text ? JSON.parse(text) : undefined) as T;
}

/** Status-only request used by probes; never throws on HTTP errors (0 = no response). */
export async function statusOf(url: string, init: RequestInit = {}): Promise<number> {
	try {
		const res = await fetch(url, { ...init, signal: AbortSignal.timeout(20_000) });
		await res.arrayBuffer();
		return res.status;
	} catch {
		return 0;
	}
}

export function probeFromStatus(status: number, what: string, expect: number | number[] = 200): ProbeResult {
	const ok = Array.isArray(expect) ? expect.includes(status) : status === expect;
	return { ok, detail: `${what} → HTTP ${status || 'no response'}` };
}

export interface RunResult {
	code: number;
	stdout: string;
	stderr: string;
}

/**
 * Run a CLI. Secrets go through stdin, never argv, so they stay out of `ps`
 * and shell history (the `op item edit` assignments are the documented
 * exception). `env` is merged over process.env.
 */
export async function run(
	cmd: string[],
	opts: { stdin?: string; cwd?: string; allowFail?: boolean; env?: Record<string, string | undefined> } = {}
): Promise<RunResult> {
	const [bin, ...args] = cmd;
	if (!bin) throw new Error('run: empty command');
	return new Promise((resolve, reject) => {
		const child = spawn(bin, args, {
			cwd: opts.cwd,
			env: { ...process.env, ...(opts.env ?? {}) },
			stdio: [opts.stdin === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
		});
		let stdout = '';
		let stderr = '';
		child.stdout?.on('data', (d: Buffer) => (stdout += d.toString()));
		child.stderr?.on('data', (d: Buffer) => (stderr += d.toString()));
		child.on('error', (e) => reject(new Error(`\`${bin}\` could not start: ${e.message}`)));
		child.on('close', (code) => {
			const c = code ?? 1;
			if (c !== 0 && !opts.allowFail) {
				reject(
					new Error(`\`${bin} ${args.slice(0, 2).join(' ')}…\` exited ${c}: ${stderr.trim() || stdout.trim()}`)
				);
				return;
			}
			resolve({ code: c, stdout, stderr });
		});
		if (opts.stdin !== undefined) {
			child.stdin!.end(opts.stdin);
		}
	});
}

export function makeLogger(dryRun: boolean, out: (line: string) => void = (l) => console.log(l)): Logger {
	const tag = dryRun ? '[dry-run] ' : '';
	return {
		info: (m) => out(m),
		step: (m) => out(`${tag}▶ ${m}`),
		warn: (m) => out(`${tag}⚠ ${m}`),
		note: (m) => out(`  ${m}`),
	};
}

/** Read a line from the terminal without echoing it; from a pipe, the whole input. */
export async function readHidden(promptText: string): Promise<string> {
	const stdin = process.stdin;
	if (!stdin.isTTY) {
		const chunks: Buffer[] = [];
		for await (const chunk of stdin) chunks.push(chunk as Buffer);
		return Buffer.concat(chunks).toString('utf8').trim();
	}
	process.stderr.write(promptText);
	stdin.setRawMode(true);
	stdin.resume();
	stdin.setEncoding('utf8');
	let buf = '';
	return new Promise((resolve) => {
		const onData = (chunk: string) => {
			for (const ch of chunk) {
				if (ch === '\r' || ch === '\n') {
					stdin.setRawMode(false);
					stdin.pause();
					stdin.off('data', onData);
					process.stderr.write('\n');
					resolve(buf.trim());
					return;
				}
				if (ch === '\u0003') process.exit(130);
				if (ch === '\u007f' || ch === '\b') buf = buf.slice(0, -1);
				else buf += ch;
			}
		};
		stdin.on('data', onData);
	});
}

/** `${KEY}` placeholders replaced from values; unknown keys are left as-is. */
export function interpolate(template: string, values: Values): string {
	return template.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (m, k: string) => values[k] ?? m);
}
