import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Ctx, Target, Values } from '../types.ts';
import { redact, run } from '../util.ts';

export interface CloudflareTargetConfig {
	kind: 'cloudflare';
	/** Directory holding wrangler.toml, relative to the manifest. */
	cwd: string;
	/** Worker name when wrangler.toml has several (passed as --name). */
	workerName?: string;
	/** Command prefix (default: `node_modules/.bin/wrangler` under cwd when present, else ["npx", "wrangler"]). */
	bin?: string[];
	/** Operator variable with an API token (default CLOUDFLARE_API_TOKEN when set, else the wrangler login). */
	token?: string;
}

/** Cloudflare Worker secrets through wrangler. Write-only: `secret list` gives names, never values. */
export class CloudflareTarget implements Target {
	readonly label: string;
	readonly readable = false;
	readonly name: string;
	private readonly cfg: CloudflareTargetConfig;
	private readonly runner: typeof run;

	constructor(cfg: CloudflareTargetConfig, name: string, runner: typeof run = run) {
		this.cfg = cfg;
		this.name = name;
		this.runner = runner;
		this.label = `Cloudflare Worker secrets (${cfg.cwd}${cfg.workerName ? `, ${cfg.workerName}` : ''})`;
	}

	private async opts(ctx: Ctx) {
		const token = await ctx.operator.get(this.cfg.token ?? 'CLOUDFLARE_API_TOKEN');
		const account = await ctx.operator.get('CLOUDFLARE_ACCOUNT_ID');
		return {
			cwd: resolve(ctx.root, this.cfg.cwd),
			env: { ...(token ? { CLOUDFLARE_API_TOKEN: token } : {}), ...(account ? { CLOUDFLARE_ACCOUNT_ID: account } : {}) },
		};
	}

	private cmd(ctx: Ctx, ...args: string[]): string[] {
		const local = resolve(ctx.root, this.cfg.cwd, 'node_modules/.bin/wrangler');
		const bin = this.cfg.bin ?? (existsSync(local) ? [local] : ['npx', 'wrangler']);
		return [...bin, ...args, ...(this.cfg.workerName ? ['--name', this.cfg.workerName] : [])];
	}

	async preflight(ctx: Ctx): Promise<string> {
		const dir = resolve(ctx.root, this.cfg.cwd);
		if (!existsSync(dir)) throw new Error(`wrangler: ${dir} does not exist (check the target's cwd and the manifest's root)`);
		const res = await this.runner(this.cmd(ctx, 'whoami'), { ...(await this.opts(ctx)), allowFail: true });
		if (res.code !== 0) throw new Error(`wrangler: not authenticated (wrangler login, or CLOUDFLARE_API_TOKEN in the operator env)`);
		const who = res.stdout.split('\n').find((l) => /logged in|associated with/i.test(l))?.trim();
		return `wrangler: ${who ?? 'authenticated'}`;
	}

	async read(keys: string[], ctx: Ctx): Promise<Record<string, Values>> {
		const res = await this.runner(this.cmd(ctx, 'secret', 'list'), await this.opts(ctx));
		const json = res.stdout.slice(res.stdout.indexOf('['));
		const names = new Set((JSON.parse(json) as { name: string }[]).map((s) => s.name));
		return { [this.cfg.workerName ?? this.cfg.cwd]: Object.fromEntries(keys.filter((k) => names.has(k)).map((k) => [k, ''])) };
	}

	async set(values: Values, ctx: Ctx): Promise<void> {
		for (const [k, v] of Object.entries(values)) ctx.log.step(`Cloudflare ${this.cfg.cwd}: secret ${k} ← ${redact(v)}`);
		if (!ctx.apply || !Object.keys(values).length) return;
		// one `secret bulk` = one new Worker version carrying every value
		await this.runner(this.cmd(ctx, 'secret', 'bulk'), { ...(await this.opts(ctx)), stdin: JSON.stringify(values) });
	}
}
