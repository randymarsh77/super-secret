/** Env-var name → value. Values are secrets: never log them, use redact(). */
export type Values = Record<string, string>;

export interface Logger {
	info(msg: string): void;
	step(msg: string): void;
	warn(msg: string): void;
	note(msg: string): void;
}

/**
 * Where secrets live between rotations. 1Password is the intended store; an
 * env file is the bootstrap store (and the import source). Rotators and
 * targets never care which is in use.
 */
export interface SecretStore {
	readonly label: string;
	get(key: string): Promise<string | undefined>;
	/** Every current value the store holds, when it can enumerate them. */
	getAll?(): Promise<Values>;
	set(values: Values): Promise<void>;
	/** The value a key held before its last set(), when the store keeps a backup slot. */
	getPrevious?(key: string): Promise<string | undefined>;
	/** ISO time the current value took over, when the store records it. */
	getRotatedAt?(key: string): Promise<string | undefined>;
	/** Drop the backup slot for a key (after its old value is revoked). */
	clearPrevious?(keys: string[]): Promise<void>;
}

/** Credentials the operator (not the app) needs: provider admin keys, deploy tokens. */
export interface OperatorEnv {
	/** process.env first, then the operator item in the vault. */
	get(name: string): Promise<string | undefined>;
	require(name: string, hint?: string): Promise<string>;
}

export interface ProbeResult {
	ok: boolean;
	detail: string;
}

/**
 * A serialisable instruction to retire an old credential once the new one is
 * verified. `manual` is understood by the pipeline; every other kind is
 * handed back to the rotator that produced it.
 */
export interface RevokeDescriptor {
	kind: string;
	/** One line for `status` and the dry run. Never a value. */
	summary: string;
	[detail: string]: unknown;
}

export interface Provisioned {
	/** New values to write to the store and push to targets. */
	values: Values;
	/** Old credentials to retire after the new ones pass their probe. */
	revoke: RevokeDescriptor[];
	notes?: string[];
}

export interface Rotator {
	/** Needs a human at a terminal (pastes a value minted in a dashboard). */
	readonly manual?: boolean;
	/** Never rotates: identifiers, usernames, DSNs. Import and push only. */
	readonly static?: boolean;
	/** Read-only checks that provider access is in place. Lines are shown with ✓. */
	preflight(ctx: Ctx, def: SecretDef): Promise<string[]>;
	/** Dry-run description. May make read-only calls. */
	plan(ctx: Ctx, def: SecretDef): Promise<string[]>;
	/** Create the new credential(s). Only called with ctx.apply === true. */
	provision(ctx: Ctx, def: SecretDef): Promise<Provisioned>;
	/** Check that the given values work against the provider. */
	probe(values: Values, ctx: Ctx, def: SecretDef): Promise<ProbeResult>;
	/** Retire a descriptor this rotator produced (kinds other than `manual`). */
	revoke?(descriptor: RevokeDescriptor, ctx: Ctx, def: SecretDef): Promise<void>;
}

/**
 * Somewhere a value is consumed: a Railway service's variables, a GitHub
 * Actions secret, a Cloudflare Worker secret, a local env file. A target
 * reports what it holds per scope (service, repo, worker) when it can read
 * values back, or just the key names when the platform is write-only.
 */
export interface Target {
	readonly label: string;
	/** true: read() returns values; false: read() returns key → '' for present keys. */
	readonly readable: boolean;
	/** Auth check; the returned line is shown with ✓. Throw to fail preflight. */
	preflight(ctx: Ctx): Promise<string>;
	/** scope label → values (or presence) for the requested keys. */
	read(keys: string[], ctx: Ctx): Promise<Record<string, Values>>;
	set(values: Values, ctx: Ctx): Promise<void>;
	/** Make the pushed values live (redeploy). Omitted when set() is enough. */
	deploy?(ctx: Ctx): Promise<void>;
}

/** true = same key names on the target; a map renames store key → target key. */
export type TargetBinding = true | Record<string, string>;

export interface SecretDef {
	id: string;
	description?: string;
	/** Env-var names this secret produces; written to the store and pushed to targets. */
	keys: string[];
	/** target name → binding. Absent = store only. */
	targets: Record<string, TargetBinding>;
	rotator: Rotator;
	/** What rotating this interrupts, for the plan output. */
	disruption?: string;
}

export interface Ctx {
	store: SecretStore;
	/** false = dry run: describe, read, never write. */
	apply: boolean;
	log: Logger;
	operator: OperatorEnv;
	targets: Record<string, Target>;
	/** Directory the manifest lives in; relative paths resolve against it. */
	root: string;
	/** Where pending revocations are kept. */
	stateDir: string;
}

/** The keys a target receives for a secret, as store key → target key. */
export function boundKeys(def: SecretDef, target: string): Record<string, string> {
	const binding = def.targets[target];
	if (!binding) return {};
	if (binding === true) return Object.fromEntries(def.keys.map((k) => [k, k]));
	return Object.fromEntries(Object.entries(binding).filter(([k]) => def.keys.includes(k)));
}
