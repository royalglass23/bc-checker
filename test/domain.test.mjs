import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyEvent, consentEvents, consentIdentity, isIssued, jobPage, latestConsentEvents, selectExactProperty } from '../src/domain.mjs';

test('monitored jobs default to five per page and clamp page requests', () => {
  assert.deepEqual(jobPage(null, null, 12), { size: 5, pages: 3, page: 1, offset: 0 });
  assert.deepEqual(jobPage('10', '2', 24), { size: 10, pages: 3, page: 2, offset: 10 });
  assert.deepEqual(jobPage('20', '99', 24), { size: 20, pages: 2, page: 2, offset: 20 });
  assert.deepEqual(jobPage('50', '1', 24), { size: 50, pages: 1, page: 1, offset: 0 });
  assert.deepEqual(jobPage('500', '-1', 0), { size: 5, pages: 1, page: 1, offset: 0 });
});

test('only one exact address match is accepted', () => {
  const job = { job_address: '12 Main Street, Mount Eden, Auckland' };
  const results = [
    { Type: 4, PropertyID: 1, StreetNumber: '12', Street: 'Main Street', Suburb: 'Mount Eden' },
    { Type: 4, PropertyID: 2, StreetNumber: '12', Street: 'Main Street', Suburb: 'Ponsonby' },
  ];
  assert.equal(selectExactProperty(job, results)?.PropertyID, 1);
  assert.equal(selectExactProperty(job, [results[0], { ...results[0], PropertyID: 3 }]), null);
  assert.equal(selectExactProperty(job, [results[1]]), null);
});

test('baseline and ignored consents never reappear as new on routine checks', () => {
  const event = { number: 'BC123', date: '2026-10-20', action: 'issued', description: 'Pool fence' };
  assert.equal(classifyEvent(event, null, true), 'baseline');
  assert.equal(classifyEvent(event, { decision: 'ignored', was_issued: false }, false), 'ignored');
  assert.equal(classifyEvent(event, { decision: 'baseline', was_issued: true }, false), 'baseline');
  assert.equal(consentIdentity(event), consentIdentity({ ...event, action: 'updated' }));
});

test('a previously observed application gets one review when it becomes issued', () => {
  const event = { number: 'BC123', date: '2026-10-20', action: 'issued', description: 'Pool fence' };
  assert.equal(isIssued(event), true);
  assert.equal(classifyEvent(event, { decision: 'baseline', was_issued: false }, false), 'needs_review');
  assert.equal(classifyEvent(event, { decision: 'needs_review', was_issued: true }, false), 'needs_review');
});

test('newest status wins when a timeline includes several events for one BC', () => {
  const older = { number: 'BC123', date: '2026-10-01', action: 'applied', description: 'Pool fence' };
  const newer = { ...older, date: '2026-10-20', action: 'issued' };
  assert.deepEqual(latestConsentEvents([newer, older]), [newer]);
  assert.deepEqual(latestConsentEvents([older, newer]), [newer]);
});

test('timeline consent categories remain available for BC classification', () => {
  const events = consentEvents({ events: [
    { key: 'building_consent', date: '2026-01-01', data: { consent_number: '12345' } },
    { key: 'resource_consent', date: '2026-01-02', data: { consent_number: 'RC123' } },
  ] });
  assert.deepEqual(events.map(event => event.kind), ['building_consent', 'resource_consent']);
});
