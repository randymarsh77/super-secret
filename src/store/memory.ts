import type { SecretStore, Values } from '../types.ts';

/** Read-only store over values already in memory (a target's variables, the shell env). */
export function memoryStore(values: Values, label: string): SecretStore {
	return {
		label,
		async get(key) {
			return values[key];
		},
		async getAll() {
			return { ...values };
		},
		async set() {
			throw new Error(`${label} is read-only`);
		},
	};
}
