import { resolve } from 'node:path';
import { EnvFileStore } from '../store/envFile.ts';
import type { Ctx, Target, Values } from '../types.ts';

export interface EnvFileTargetConfig {
	kind: 'env-file';
	/** Relative to the manifest. */
	path: string;
	/** Keep a timestamped backup beside the file on each write (default true). */
	backup?: boolean;
}

/** A local env file that scripts read (the developer's .env), kept in step with the store. */
export class EnvFileTarget implements Target {
	readonly label: string;
	readonly readable = true;
	readonly name: string;
	private readonly cfg: EnvFileTargetConfig;

	constructor(cfg: EnvFileTargetConfig, name: string) {
		this.cfg = cfg;
		this.name = name;
		this.label = `env file ${cfg.path}`;
	}

	private store(ctx: Ctx) {
		return new EnvFileStore(resolve(ctx.root, this.cfg.path), ctx.apply, ctx.log, this.cfg.backup ?? true);
	}

	async preflight(): Promise<string> {
		return `env file ${this.cfg.path}`;
	}

	async read(keys: string[], ctx: Ctx): Promise<Record<string, Values>> {
		const all = await this.store(ctx).getAll();
		return { [this.cfg.path]: Object.fromEntries(keys.filter((k) => k in all).map((k) => [k, all[k]!])) };
	}

	async set(values: Values, ctx: Ctx): Promise<void> {
		await this.store(ctx).set(values);
	}
}
