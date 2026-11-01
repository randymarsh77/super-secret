import assert from 'node:assert/strict';
import { test } from 'node:test';
import { encode, parseTemplate, render } from '../src/render.ts';
import { interpolate, randomSecret, redact, sha } from '../src/util.ts';

test('redact shows a short prefix, the length and a hash, never the value', () => {
	const r = redact('sk_live_abcdefghijklmnop');
	assert.match(r, /^sk_liv…\(24 chars, sha [0-9a-f]{8}\)$/);
	assert.equal(redact(undefined), '(unset)');
	assert.equal(redact(''), '(empty)');
	assert.equal(redact('abc'), '…(3 chars, sha ' + sha('abc') + ')');
});

test('randomSecret honours length and alphabet', () => {
	assert.equal(randomSecret(40).length, 40);
	assert.match(randomSecret(40), /^[A-Za-z0-9]+$/);
	assert.match(randomSecret(16, 'hex'), /^[0-9a-f]{16}$/);
	assert.match(randomSecret(22, 'base64url'), /^[A-Za-z0-9_-]{22}$/);
	assert.notEqual(randomSecret(), randomSecret());
});

test('interpolate replaces known keys and leaves unknown placeholders', () => {
	assert.equal(interpolate('Bearer ${T} ${X}', { T: 'tok' }), 'Bearer tok ${X}');
});

test('render: references resolve through the reader, literals pass through, _B64 encodes', async () => {
	const entries = parseTemplate('# c\nA=op://v/i/A\nURL=https://x.test\nKEY_B64=op://v/i/key\n');
	assert.deepEqual(entries.map((e) => e.key), ['A', 'URL', 'KEY_B64']);
	const values = await render(entries, async (ref) => Buffer.from(ref.endsWith('/key') ? 'line1\nline2' : 'val'));
	assert.deepEqual(values, { A: 'val', URL: 'https://x.test', KEY_B64: Buffer.from('line1\nline2\n').toString('base64') });
	assert.throws(() => encode('MULTI', Buffer.from('a\nb')), /MULTI_B64/);
	assert.throws(() => parseTemplate('lower=1'), /upper-case/);
	await assert.rejects(render(parseTemplate('B=op://x'), async () => { throw new Error('nope'); }), /^Error: B: nope/);
});
