import type { OperatorConfig, StoreConfig } from './manifest.ts';
import { OnePasswordStore } from './store/onePassword.ts';
import type { Logger, OperatorEnv, SecretStore } from './types.ts';

export const OPERATOR_ITEM = 'operator';

/**
 * Operator credentials authorise the tooling itself (a Railway account token,
 * a GitHub token with secrets:write, provider admin keys). They never go in
 * the app's store. The shell env wins; otherwise they are read from the
 * `operator` item in the same vault, so CI needs exactly one secret, the
 * 1Password service-account token.
 */
export function makeOperatorEnv(store: StoreConfig, cfg: OperatorConfig | false | undefined, log: Logger): OperatorEnv & { item?: SecretStore } {
	const item =
		cfg === false || store.kind !== 'op'
			? undefined
			: new OnePasswordStore({
					vault: store.vault,
					item: cfg?.item ?? OPERATOR_ITEM,
					account: store.account,
					layout: cfg?.layout ?? store.layout,
					apply: false,
					log,
				});
	const cache = new Map<string, string | undefined>();
	return {
		item,
		async get(name) {
			const fromEnv = process.env[name];
			if (fromEnv) return fromEnv;
			if (!item) return undefined;
			if (!cache.has(name)) {
				try {
					cache.set(name, await item.get(name));
				} catch (e) {
					log.warn(`operator item: ${(e as Error).message}`);
					cache.set(name, undefined);
				}
			}
			return cache.get(name);
		},
		async require(name, hint) {
			const v = await this.get(name);
			if (v) return v;
			const where = item ? `the shell env or ${item.label} (current.${name})` : 'the shell env';
			throw new Error(`${name}${hint ? ` (${hint})` : ''} is not set in ${where}`);
		},
	};
}

/** The operator item as a writable store, for `import --operator`. */
export function operatorStore(store: StoreConfig, cfg: OperatorConfig | false | undefined, apply: boolean, log: Logger): OnePasswordStore {
	if (store.kind !== 'op' || cfg === false) throw new Error('the operator item needs an `op` store and operator not set to false');
	return new OnePasswordStore({
		vault: store.vault,
		item: cfg?.item ?? OPERATOR_ITEM,
		account: store.account,
		layout: cfg?.layout ?? store.layout,
		apply,
		log,
	});
}
