import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseEnv, upsertEnv } from '../src/store/envFile.ts';
import { createTemplate, fieldsBySection, planAssignments, slots, OnePasswordStore } from '../src/store/onePassword.ts';
import { makeLogger } from '../src/util.ts';

test('parseEnv: first wins, quotes stripped, export allowed', () => {
	const v = parseEnv('A=1\nexport B="two words"\nC=\'c\'\nA=9\n# D=4\n');
	assert.deepEqual(v, { A: '1', B: 'two words', C: 'c' });
});

test('upsertEnv: replaces in place, appends the rest in a managed block, leaves comments', () => {
	const out = upsertEnv('# header\nA=1\n# A=old\nB=2\n', { A: 'x y', C: 'z' });
	assert.equal(out, '# header\nA="x y"\n# A=old\nB=2\n\n# Managed by super-secret\nC=z\n');
});

test('fieldsBySection groups by section label; unsectioned under ""', () => {
	const f = fieldsBySection({
		id: 'i',
		title: 't',
		fields: [
			{ id: 'a', label: 'K', value: 'v', section: { id: 'current', label: 'current' } },
			{ id: 'b', label: 'K', value: 'old', section: { id: 'previous', label: 'previous' } },
			{ id: 'c', label: 'notesPlain', value: '' },
			{ id: 'd', label: 'X', value: 'flat' },
		],
	});
	assert.deepEqual(f, { current: { K: 'v' }, previous: { K: 'old' }, '': { X: 'flat' } });
});

test('planAssignments (sections): changed value moves to previous with a stamp; new key just sets current', () => {
	const now = new Date('2026-01-02T03:04:05.000Z');
	const plan = planAssignments({ current: { A: 'old' } }, { A: 'new', B: 'b' }, 'sections', now);
	assert.deepEqual(
		plan.map((a) => a.arg),
		['previous.A[password]=old', 'meta.A_rotated_at[text]=2026-01-02T03:04:05.000Z', 'current.A[password]=new', 'current.B[password]=b']
	);
	assert.equal(planAssignments({ current: { A: 'same' } }, { A: 'same' }).length, 1);
});

test('planAssignments (flat): suffixes instead of sections', () => {
	const plan = planAssignments({ '': { A: 'old' } }, { A: 'new' }, 'flat', new Date(0));
	assert.deepEqual(
		plan.map((a) => a.arg),
		['A_previous[password]=old', 'A_rotated_at[text]=1970-01-01T00:00:00.000Z', 'A[password]=new']
	);
	assert.deepEqual(slots('flat', 'A').current, ['', 'A']);
});

test('createTemplate: concealed fields in sections, a rotated_at per key', () => {
	const t = createTemplate('production', { A: '1' }, 'sections', new Date(0));
	assert.equal(t.category, 'SECURE_NOTE');
	assert.deepEqual(t.sections, [{ id: 'current', label: 'current' }, { id: 'meta', label: 'meta' }]);
	assert.deepEqual(
		t.fields.map((f) => [f.label, f.type, (f.section as { id: string } | undefined)?.id]),
		[['A', 'CONCEALED', 'current'], ['A_rotated_at', 'STRING', 'meta']]
	);
	const flat = createTemplate('prod', { A: '1' }, 'flat');
	assert.deepEqual(flat.sections, []);
	assert.equal(flat.fields[0]!.section, undefined);
});

test('OnePasswordStore: reads through op, creates via template when the item is missing, edits otherwise', async () => {
	const calls: string[][] = [];
	let exists = false;
	const runner = (async (cmd: string[]) => {
		calls.push(cmd);
		if (cmd[1] === 'item' && cmd[2] === 'get') {
			if (!exists) return { code: 1, stdout: '', stderr: `[ERROR] "production" isn't an item in the "v" vault` };
			return { code: 0, stdout: JSON.stringify({ id: 'x', title: 'production', fields: [{ id: 'a', label: 'A', value: 'old', section: { id: 'current', label: 'current' } }] }), stderr: '' };
		}
		if (cmd[2] === 'create') exists = true;
		return { code: 0, stdout: '', stderr: '' };
	}) as never;
	const lines: string[] = [];
	const store = new OnePasswordStore({ vault: 'v', item: 'production', account: 'acct', apply: true, log: makeLogger(false, (l) => lines.push(l)), runner });
	assert.equal(await store.get('A'), undefined);
	await store.set({ A: 'old' });
	const create = calls.find((c) => c[2] === 'create')!;
	assert.ok(create.includes('--template'), 'new items go through a template file');
	assert.ok(!create.some((a) => a.includes('=old')), 'values stay off argv on create');
	assert.deepEqual(create.slice(-4), ['--vault', 'v', '--account', 'acct']);
	await store.set({ A: 'new' });
	const edit = calls.find((c) => c[2] === 'edit')!;
	assert.ok(edit.includes('previous.A[password]=old') && edit.includes('current.A[password]=new'));
	assert.equal(store.reference('A'), 'op://v/production/current/A');
	assert.ok(lines.every((l) => !l.includes('new') || l.includes('…')), 'values are redacted in the log');
});
