import type { Ctx, Target, Values } from '../types.ts';
import { redact, run } from '../util.ts';

export interface GithubTargetConfig {
	kind: 'github';
	/** owner/name */
	repo: string;
	/** A GitHub Environment's secrets instead of the repository's. */
	environment?: string;
	/** Operator variable with a token for `gh` (default: GH_TOKEN when set, else the gh login). */
	token?: string;
}

/** GitHub Actions secrets through the `gh` CLI. Write-only: names are listed, values never read back. */
export class GithubTarget implements Target {
	readonly label: string;
	readonly readable = false;
	readonly name: string;
	private readonly cfg: GithubTargetConfig;
	private readonly runner: typeof run;

	constructor(cfg: GithubTargetConfig, name: string, runner: typeof run = run) {
		this.cfg = cfg;
		this.name = name;
		this.runner = runner;
		this.label = `GitHub ${cfg.repo}${cfg.environment ? ` env ${cfg.environment}` : ''} secrets`;
	}

	private async env(ctx: Ctx): Promise<Record<string, string | undefined>> {
		const token = await ctx.operator.get(this.cfg.token ?? 'GH_TOKEN');
		return token ? { GH_TOKEN: token } : {};
	}

	private scope(): string[] {
		return ['-R', this.cfg.repo, ...(this.cfg.environment ? ['--env', this.cfg.environment] : [])];
	}

	async preflight(ctx: Ctx): Promise<string> {
		const env = await this.env(ctx);
		const res = await this.runner(['gh', 'auth', 'status'], { allowFail: true, env });
		if (res.code !== 0) throw new Error('gh: not authenticated (gh auth login, or GH_TOKEN in the operator env)');
		return `gh: authenticated for ${this.cfg.repo}`;
	}

	async read(keys: string[], ctx: Ctx): Promise<Record<string, Values>> {
		const res = await this.runner(['gh', 'secret', 'list', ...this.scope(), '--json', 'name'], { env: await this.env(ctx) });
		const names = new Set((JSON.parse(res.stdout) as { name: string }[]).map((s) => s.name));
		return { [this.cfg.repo]: Object.fromEntries(keys.filter((k) => names.has(k)).map((k) => [k, ''])) };
	}

	async set(values: Values, ctx: Ctx): Promise<void> {
		const env = await this.env(ctx);
		for (const [key, value] of Object.entries(values)) {
			ctx.log.step(`GitHub ${this.cfg.repo}: secret ${key} ← ${redact(value)}`);
			if (!ctx.apply) continue;
			await this.runner(['gh', 'secret', 'set', key, ...this.scope()], { stdin: value, env });
		}
	}
}
