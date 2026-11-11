import assert from 'node:assert/strict';
import { afterEach, test } from 'node:test';
import { cloudflareApiTokenRotator } from '../src/rotators/cloudflareToken.ts';
import { PRESETS, locateCloudflareToken } from '../src/rotators/probes.ts';
import { memoryStore } from '../src/store/memory.ts';
import type { Ctx } from '../src/types.ts';
import { makeLogger } from '../src/util.ts';

const API = 'https://api.cloudflare.com/client/v4';
const realFetch = globalThis.fetch;
afterEach(() => {
	globalThis.fetch = realFetch;
});

type Route = { status: number; body: unknown };
/** Stub fetch with a `METHOD path` → response table; records every call. */
function stub(routes: Record<string, Route>): string[] {
	const calls: string[] = [];
	globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const key = `${init?.method ?? 'GET'} ${String(input).replace(API, '')}`;
		calls.push(key);
		const r = routes[key] ?? { status: 404, body: { success: false } };
		return new Response(JSON.stringify(r.body), { status: r.status });
	}) as typeof fetch;
	return calls;
}

const invalid: Route = { status: 401, body: { success: false, errors: [{ code: 1000, message: 'Invalid API Token' }] } };
const active = (id: string): Route => ({ status: 200, body: { success: true, result: { id, status: 'active' } } });

function ctx(values: Record<string, string>): Ctx {
	return {
		store: memoryStore(values, 'mem'),
		apply: true,
		log: makeLogger(false, () => {}),
		operator: { get: async () => undefined, require: async () => '' },
		targets: {},
		root: '/',
		stateDir: '/tmp',
	};
}

test('a user-owned token verifies at /user/tokens and nothing else is asked', async () => {
	const calls = stub({ 'GET /user/tokens/verify': active('tok-u') });
	const r = await locateCloudflareToken('t');
	assert.equal(r.ok, true);
	assert.equal(r.base, `${API}/user/tokens`);
	assert.equal(r.account, undefined);
	assert.deepEqual(calls, ['GET /user/tokens/verify']);
});

test('an account-owned token is not dead because /user/tokens says 401: its account is discovered and verified', async () => {
	const calls = stub({
		'GET /user/tokens/verify': invalid,
		'GET /accounts': { status: 200, body: { success: true, result: [{ id: 'acc-1' }] } },
		'GET /accounts/acc-1/tokens/verify': active('tok-a'),
	});
	const r = await PRESETS['cloudflare-token']('cfat_x');
	assert.equal(r.ok, true);
	assert.match(r.detail, /account token \(account acc-1\).*active/);
	assert.deepEqual(calls, ['GET /user/tokens/verify', 'GET /accounts', 'GET /accounts/acc-1/tokens/verify']);
});

test('a given account skips discovery', async () => {
	const calls = stub({ 'GET /user/tokens/verify': invalid, 'GET /accounts/acc-9/tokens/verify': active('tok-a') });
	const r = await locateCloudflareToken('t', 'acc-9');
	assert.equal(r.ok, true);
	assert.equal(r.base, `${API}/accounts/acc-9/tokens`);
	assert.deepEqual(calls, ['GET /user/tokens/verify', 'GET /accounts/acc-9/tokens/verify']);
});

test('a token neither endpoint knows is invalid, and the detail says what was tried', async () => {
	stub({
		'GET /user/tokens/verify': invalid,
		'GET /accounts': { status: 200, body: { success: true, result: [{ id: 'acc-1' }] } },
		'GET /accounts/acc-1/tokens/verify': invalid,
	});
	const r = await locateCloudflareToken('t');
	assert.equal(r.ok, false);
	assert.match(r.detail, /user tokens\/verify → HTTP 401; GET \/accounts → HTTP 200, 1 account\(s\); account acc-1 tokens\/verify → HTTP 401/);
});

test('a recognised but inactive token is invalid without falling through to accounts', async () => {
	const calls = stub({ 'GET /user/tokens/verify': { status: 200, body: { success: true, result: { id: 'tok-u', status: 'disabled' } } } });
	const r = await locateCloudflareToken('t');
	assert.equal(r.ok, false);
	assert.match(r.detail, /status disabled/);
	assert.equal(calls.length, 1);
});

test('the rotator rolls an account-owned token at its account endpoint, account id from the store', async () => {
	const calls = stub({
		'GET /user/tokens/verify': invalid,
		'GET /accounts/acc-1/tokens/verify': active('tok-a'),
		'PUT /accounts/acc-1/tokens/tok-a/value': { status: 200, body: { success: true, result: 'new-value' } },
	});
	const rot = cloudflareApiTokenRotator({ kind: 'cloudflare-api-token', account: '${CLOUDFLARE_ACCOUNT_ID}' });
	const out = await rot.provision(ctx({ CLOUDFLARE_API_TOKEN: 'old', CLOUDFLARE_ACCOUNT_ID: 'acc-1' }), {} as never);
	assert.deepEqual(out.values, { CLOUDFLARE_API_TOKEN: 'new-value' });
	assert.equal(calls.at(-1), 'PUT /accounts/acc-1/tokens/tok-a/value');
});

test('the rotator still rolls a user-owned token at /user/tokens', async () => {
	const calls = stub({
		'GET /user/tokens/verify': active('tok-u'),
		'PUT /user/tokens/tok-u/value': { status: 200, body: { success: true, result: 'new-value' } },
	});
	const out = await cloudflareApiTokenRotator().provision(ctx({ CLOUDFLARE_API_TOKEN: 'old' }), {} as never);
	assert.deepEqual(out.values, { CLOUDFLARE_API_TOKEN: 'new-value' });
	assert.equal(calls.at(-1), 'PUT /user/tokens/tok-u/value');
});

test('a roll the token may not perform names the permission for its kind', async () => {
	stub({
		'GET /user/tokens/verify': invalid,
		'GET /accounts': { status: 200, body: { success: true, result: [{ id: 'acc-1' }] } },
		'GET /accounts/acc-1/tokens/verify': active('tok-a'),
		'PUT /accounts/acc-1/tokens/tok-a/value': { status: 403, body: { success: false } },
	});
	await assert.rejects(cloudflareApiTokenRotator().provision(ctx({ CLOUDFLARE_API_TOKEN: 'old' }), {} as never), /Account API Tokens/);
});
