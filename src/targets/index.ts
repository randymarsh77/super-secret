import type { Target } from '../types.ts';
import { CloudflareTarget, type CloudflareTargetConfig } from './cloudflare.ts';
import { EnvFileTarget, type EnvFileTargetConfig } from './envFile.ts';
import { GithubTarget, type GithubTargetConfig } from './github.ts';
import { RailwayTarget, type RailwayTargetConfig } from './railway.ts';

export type TargetConfig = RailwayTargetConfig | GithubTargetConfig | CloudflareTargetConfig | EnvFileTargetConfig;

export function createTarget(name: string, cfg: TargetConfig | Target): Target {
	if (!('kind' in cfg)) return cfg;
	switch (cfg.kind) {
		case 'railway':
			return new RailwayTarget(cfg, name);
		case 'github':
			return new GithubTarget(cfg, name);
		case 'cloudflare':
			return new CloudflareTarget(cfg, name);
		case 'env-file':
			return new EnvFileTarget(cfg, name);
		default:
			throw new Error(`target ${name}: unknown kind ${String((cfg as { kind: unknown }).kind)}`);
	}
}

export { CloudflareTarget, EnvFileTarget, GithubTarget, RailwayTarget, gqlClient } from './all.ts';
export type { CloudflareTargetConfig, EnvFileTargetConfig, GithubTargetConfig, RailwayTargetConfig };
