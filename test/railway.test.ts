import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RailwayTarget } from '../src/targets/railway.ts';
import { memoryStore } from '../src/store/memory.ts';
import type { Ctx } from '../src/types.ts';
import { makeLogger } from '../src/util.ts';

function fakeGql(log: Array<{ query: string; variables: any }>) {
	return async (query: string, variables: any) => {
		log.push({ query, variables });
		if (query.includes('me {')) return { me: { email: 'op@example.com' } };
		if (query.includes('project(id')) return { project: { services: { edges: [{ node: { id: 'svc-1', name: 'compute' } }, { node: { id: 'svc-2', name: 'bench' } }] } } };
		if (query.includes('variables(')) return { variables: variables.s === 'svc-1' ? { WORKER_TOKEN: 'old', KEEP: '1' } : {} };
		if (query.includes('environment(id')) return { environment: { config: { services: { 'svc-1': { source: { image: 'ghcr.io/x/y:tag' } } } } } };
		return {};
	};
}

function ctx(apply: boolean): Ctx {
	return {
		store: memoryStore({ RAILWAY_PROJECT_ID: 'proj', GHCR_USERNAME: 'me', GHCR_READ_TOKEN: 'ghp_x' }, 'mem'),
		apply,
		log: makeLogger(!apply, () => {}),
		operator: { get: async (n) => (n === 'RAILWAY_API_TOKEN' ? 'tok' : undefined), require: async () => 'tok' },
		targets: {},
		root: '/',
		stateDir: '/tmp',
	};
}

test('RailwayTarget resolves services by name, reads per service, upserts with skipDeploys, sets registry creds with the image', async () => {
	const calls: Array<{ query: string; variables: any }> = [];
	const t = new RailwayTarget(
		{ kind: 'railway', project: '${RAILWAY_PROJECT_ID}', environment: 'env-1', services: ['compute', 'bench'], registryCredentials: { username: 'GHCR_USERNAME', password: 'GHCR_READ_TOKEN' } },
		'rw',
		() => fakeGql(calls)
	);
	const c = ctx(true);
	assert.match(await t.preflight(c), /op@example.com; services compute, bench/);
	assert.deepEqual(await t.read(['WORKER_TOKEN', 'NOPE'], c), { compute: { WORKER_TOKEN: 'old' }, bench: {} });
	await t.set({ WORKER_TOKEN: 'new', GHCR_READ_TOKEN: 'ghp_y' }, c);
	const upserts = calls.filter((x) => x.query.includes('variableCollectionUpsert'));
	assert.equal(upserts.length, 2);
	assert.deepEqual(upserts[0]!.variables.input, { projectId: 'proj', environmentId: 'env-1', serviceId: 'svc-1', variables: { WORKER_TOKEN: 'new' }, skipDeploys: true });
	const creds = calls.filter((x) => x.query.includes('serviceInstanceUpdate'));
	assert.equal(creds.length, 2);
	assert.deepEqual(creds[0]!.variables.input, { source: { image: 'ghcr.io/x/y:tag' }, registryCredentials: { username: 'me', password: 'ghp_y' } });
	assert.deepEqual(creds[1]!.variables.input, { registryCredentials: { username: 'me', password: 'ghp_y' } });
});

test('RailwayTarget fails loudly on an unknown service and writes nothing in dry run', async () => {
	const calls: Array<{ query: string; variables: any }> = [];
	const t = new RailwayTarget({ kind: 'railway', project: 'p', environment: 'e', services: ['ghost'] }, 'rw', () => fakeGql(calls));
	await assert.rejects(t.preflight(ctx(true)), /ghost not in the project/);
	const t2 = new RailwayTarget({ kind: 'railway', project: 'p', environment: 'e', services: ['compute'] }, 'rw', () => fakeGql(calls));
	await t2.set({ A: '1' }, ctx(false));
	assert.equal(calls.filter((x) => x.query.includes('mutation')).length, 0);
});
