import { randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { RevokeDescriptor } from './types.ts';

/**
 * Old credentials waiting to be retired. Written the moment a new credential
 * is provisioned, so a crash between "provision" and "revoke" never orphans a
 * live key; `revoke-pending` drains it.
 */
export interface PendingRevocation {
	id: string;
	secretId: string;
	createdAt: string;
	descriptor: RevokeDescriptor;
}

export class RevocationQueue {
	readonly dir: string;
	private readonly file: string;

	constructor(dir: string) {
		this.dir = dir;
		this.file = join(dir, 'pending-revocations.json');
	}

	list(): PendingRevocation[] {
		return existsSync(this.file) ? (JSON.parse(readFileSync(this.file, 'utf8')) as PendingRevocation[]) : [];
	}

	private save(items: PendingRevocation[]): void {
		mkdirSync(this.dir, { recursive: true });
		writeFileSync(this.file, JSON.stringify(items, null, 2) + '\n', { mode: 0o600 });
	}

	add(secretId: string, descriptors: RevokeDescriptor[]): PendingRevocation[] {
		const added = descriptors.map((descriptor) => ({ id: randomUUID(), secretId, createdAt: new Date().toISOString(), descriptor }));
		if (added.length) this.save([...this.list(), ...added]);
		return added;
	}

	remove(ids: string[]): void {
		this.save(this.list().filter((p) => !ids.includes(p.id)));
	}
}
