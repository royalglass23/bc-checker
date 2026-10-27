import assert from 'node:assert/strict';
import { test } from 'node:test';
import { bcStatus, mergeBcStatus } from '../src/bc-note.mjs';

const checkedAt = new Date('2026-10-28T00:30:00Z');

test('Note status uses the latest classified BC within three years', () => {
  const events = [
    { number: 'BC111', date: '2022-10-28', action: 'Issued', description: 'Building consent' },
    { number: 'RC222', date: '2026-10-20', action: 'Issued', description: 'Resource consent' },
    { number: 'BC333', date: '2025-04-01', action: 'Issued', description: 'Building consent' },
  ];
  assert.equal(bcStatus(events, checkedAt), 'BC - BC333 - 28 Oct 2026');
  assert.equal(bcStatus(events.slice(0, 2), checkedAt), 'NO BC - 28 Oct 2026');
  assert.equal(bcStatus([{ kind: 'building_consent', number: '12345', date: '2026-01-01', action: 'Issued' }], checkedAt),
    'BC - 12345 - 28 Oct 2026');
});

test('Note status replaces the prior BC block or concise status while preserving staff text', () => {
  assert.equal(mergeBcStatus('Staff note | [BC CHECK]old details[/BC CHECK]', 'NO BC - 28 Oct 2026'),
    'Staff note | NO BC - 28 Oct 2026');
  assert.equal(mergeBcStatus('Staff note | NO BC - 20 Oct 2026', 'BC - BC333 - 28 Oct 2026'),
    'Staff note | BC - BC333 - 28 Oct 2026');
  assert.equal(mergeBcStatus('Staff note | BC - BC333 - 28 Oct 2026', 'NO BC - 29 Oct 2026'),
    'Staff note | NO BC - 29 Oct 2026');
  assert.equal(mergeBcStatus('Staff note [BC CHECK]incomplete', 'NO BC - 28 Oct 2026'), null);
});
