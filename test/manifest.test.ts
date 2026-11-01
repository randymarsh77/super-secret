import assert from 'node:assert/strict';
import { test } from 'node:test';
import { resolveManifest, selectSecrets, validateManifest, type ManifestConfig } from '../src/manifest.ts';
import { boundKeys } from '../src/types.ts';

const good: ManifestConfig = {
	store: { kind: 'op', vault: 'v', item: 'production' },
	targets: { gh: { kind: 'github', repo: 'o/r' }, cf: { kind: 'cloudflare', cwd: 'worker' } },
	secrets: [
		{ id: 'token', keys: ['TOKEN'], targets: { gh: true, cf: { TOKEN: 'WORKER_TOKEN' } }, rotator: { kind: 'generated', length: 40 } },
		{ id: 'id', keys: ['PROJECT_ID'], rotator: { kind: 'static' } },
		{ id: 'pat', keys: ['PAT'], rotator: { kind: 'manual', create: 'GitHub → tokens', probe: { kind: 'github-token' } } },
	],
};

test('validateManifest accepts a good manifest', () => {
	assert.deepEqual(validateManifest(good), []);
});

test('validateManifest names each problem', () => {
	const errors = validateManifest({
		store: { kind: 'op', vault: '', item: 'x' },
		targets: { Bad: { kind: 'github', repo: 'o/r' } },
		secrets: [
			{ id: 'a', keys: ['K'], targets: { nope: true }, rotator: { kind: 'manual' } as never },
			{ id: 'a', keys: ['K', 'bad key'], rotator: { kind: 'generated' } },
			{ id: 'w', keys: ['W'], targets: { Bad: { Z: 'W' } }, rotator: { kind: 'stripe-webhook-secret' } as never },
		],
	} as ManifestConfig);
	for (const needle of ['store.vault', 'target "Bad"', 'target "nope" is not defined', 'manual rotator needs', 'duplicate id', 'already belongs to a', 'not an env var name', 'maps Z', 'needs `url`'])
		assert.ok(errors.some((e) => e.includes(needle)), `missing error about ${needle}: ${errors.join(' | ')}`);
});

test('resolveManifest builds targets and rotators; boundKeys honours renames', () => {
	const { targets, secrets } = resolveManifest(good);
	assert.deepEqual(Object.keys(targets).sort(), ['cf', 'gh']);
	assert.equal(targets.gh!.readable, false);
	const token = secrets.find((s) => s.id === 'token')!;
	assert.deepEqual(boundKeys(token, 'gh'), { TOKEN: 'TOKEN' });
	assert.deepEqual(boundKeys(token, 'cf'), { TOKEN: 'WORKER_TOKEN' });
	assert.deepEqual(boundKeys(token, 'none'), {});
	assert.equal(secrets.find((s) => s.id === 'id')!.rotator.static, true);
	assert.equal(secrets.find((s) => s.id === 'pat')!.rotator.manual, true);
	assert.deepEqual(selectSecrets(secrets, ['pat']).map((s) => s.id), ['pat']);
	assert.throws(() => selectSecrets(secrets, ['zzz']), /unknown secret id/);
});
