import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { resolveManifest } from '../src/manifest.ts';
import { push, rotate, status, verify } from '../src/pipeline.ts';
import { memoryStore } from '../src/store/memory.ts';
import { RevocationQueue } from '../src/state.ts';
import type { Ctx, SecretStore, Target, Values } from '../src/types.ts';
import { makeLogger } from '../src/util.ts';

function fakeStore(initial: Values): SecretStore & { writes: Values[] } {
	const data = { ...initial };
	const writes: Values[] = [];
	return {
		label: 'fake store',
		writes,
		async get(k) {
			return data[k];
		},
		async set(v) {
			writes.push(v);
			Object.assign(data, v);
		},
	};
}

function fakeTarget(readable: boolean, remote: Values): Target & { sets: Values[]; deploys: number } {
	const t = {
		label: 'fake target',
		readable,
		sets: [] as Values[],
		deploys: 0,
		async preflight() {
			return 'ok';
		},
		async read(keys: string[]) {
			return { scope: Object.fromEntries(keys.filter((k) => k in remote).map((k) => [k, readable ? remote[k]! : ''])) };
		},
		async set(values: Values) {
			t.sets.push(values);
		},
		async deploy() {
			t.deploys++;
		},
	};
	return t;
}

function ctxWith(store: SecretStore, targets: Record<string, Target>, apply: boolean, lines: string[]): Ctx {
	const dir = mkdtempSync(join(tmpdir(), 'ss-test-'));
	return {
		store,
		apply,
		log: makeLogger(!apply, (l) => lines.push(l)),
		operator: { get: async () => undefined, require: async (n) => { throw new Error(n); } },
		targets,
		root: dir,
		stateDir: join(dir, '.state'),
	};
}

const { secrets } = resolveManifest({
	store: { kind: 'env', file: '.env' },
	targets: { a: { kind: 'env-file', path: 'x' }, b: { kind: 'github', repo: 'o/r' } },
	secrets: [
		{ id: 'tok', keys: ['TOK'], targets: { a: true, b: { TOK: 'GH_TOK' } }, rotator: { kind: 'generated', length: 12 } },
		{ id: 'id', keys: ['ID'], targets: { a: true }, rotator: { kind: 'static' } },
	],
});

test('push: readable target gets only differing keys, write-only target gets every bound key, deploy once per changed target', async () => {
	const store = fakeStore({ TOK: 't1', ID: 'i1' });
	const a = fakeTarget(true, { TOK: 't1', ID: 'old' });
	const b = fakeTarget(false, {});
	const lines: string[] = [];
	await push(secrets, ctxWith(store, { a, b }, true, lines), { deploy: true });
	assert.deepEqual(a.sets, [{ ID: 'i1' }]);
	assert.deepEqual(b.sets, [{ GH_TOK: 't1' }]);
	assert.equal(a.deploys, 1);
	assert.ok(lines.some((l) => l.includes('GH_TOK: MISSING')));
});

test('push dry run writes nothing but describes everything', async () => {
	const store = fakeStore({ TOK: 't1', ID: 'i1' });
	const a = fakeTarget(true, {});
	const lines: string[] = [];
	await push(secrets, ctxWith(store, { a }, false, lines), { deploy: true, targets: ['a'] });
	// the fake target records set() calls even in dry run; the real ones check ctx.apply
	assert.ok(lines.some((l) => l.includes('━━ fake target')));
	assert.ok(a.sets.length === 1, 'the fake target records the described set');
	assert.deepEqual(store.writes, [], 'the store is never written by push');
});

test('rotate: generated secret → store, targets, deploy, probe; static skipped; dry run uses placeholders', async () => {
	const store = fakeStore({ TOK: 't1', ID: 'i1' });
	const a = fakeTarget(true, { TOK: 't1' });
	const b = fakeTarget(false, {});
	const lines: string[] = [];
	const ctx = ctxWith(store, { a, b }, true, lines);
	Object.defineProperty(process.stdin, 'isTTY', { value: true, configurable: true });
	await rotate(secrets, ctx, { deploy: true, revoke: true });
	assert.equal(store.writes.length, 1);
	const tok = store.writes[0]!.TOK!;
	assert.equal(tok.length, 12);
	assert.deepEqual(a.sets, [{ TOK: tok }]);
	assert.deepEqual(b.sets, [{ GH_TOK: tok }]);
	assert.equal(a.deploys, 1);
	assert.ok(lines.some((l) => l.includes('id: static, not rotated')));
	assert.equal(new RevocationQueue(ctx.stateDir).list().length, 0);

	const dry = ctxWith(fakeStore({ TOK: 't1' }), { a: fakeTarget(true, {}) }, false, []);
	await rotate(secrets, dry, { deploy: true, revoke: true, targets: ['a'] });
	assert.deepEqual((dry.store as ReturnType<typeof fakeStore>).writes, [{ TOK: '<new TOK>' }]);
});

test('verify: probes current values; static secrets are skipped', async () => {
	const lines: string[] = [];
	const ok = await verify(secrets, ctxWith(fakeStore({ TOK: 'x', ID: 'y' }), {}, false, lines), false);
	assert.equal(ok, true);
	assert.ok(!lines.some((l) => l.includes('id:')));
});

test('status: shows store vs target state per scope without printing values', async () => {
	const lines: string[] = [];
	const a = fakeTarget(true, { TOK: 'different' });
	const b = fakeTarget(false, { GH_TOK: '' });
	await status(secrets, ctxWith(fakeStore({ TOK: 'secret-value-123', ID: 'i' }), { a, b }, false, lines));
	const text = lines.join('\n');
	assert.ok(text.includes('≠ store'));
	assert.ok(text.includes('b/scope as GH_TOK: present'));
	assert.ok(!text.includes('secret-value-123'));
	assert.ok(text.includes('Pending revocations: 0'));
});

test('RevocationQueue round-trips', () => {
	const dir = mkdtempSync(join(tmpdir(), 'ss-q-'));
	try {
		const q = new RevocationQueue(dir);
		const [added] = q.add('s', [{ kind: 'manual', summary: 'do it' }]);
		assert.equal(q.list().length, 1);
		q.remove([added!.id]);
		assert.equal(q.list().length, 0);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('memoryStore is read-only', async () => {
	const m = memoryStore({ A: '1' }, 'mem');
	assert.equal(await m.get('A'), '1');
	await assert.rejects(m.set({ A: '2' }), /read-only/);
});
