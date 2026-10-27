import { createHash } from 'node:crypto';

export function normaliseAddress(value) {
  return String(value ?? '').toLowerCase()
    .replace(/\b(?:new zealand|nz)\b/g, '')
    .replace(/\b\d{4}\b/g, '')
    .replace(/[^a-z0-9]+/g, ' ').replace(/\s+/g, ' ').trim();
}

export function searchStreet(job) {
  const structured = [job.geo_number, job.geo_street].filter(Boolean).join(' ').trim();
  return (structured.length >= 5 ? structured : String(job.job_address ?? '').split(/[,\r\n]/)[0])
    .replace(/\b\d{4}\b/g, '').replace(/\s+/g, ' ').trim();
}

export function selectExactProperty(job, results) {
  const query = searchStreet(job);
  const match = query.match(/^(\d+\s*[a-z]?)\s+(.+)$/i);
  if (!match) return null;
  const number = normaliseAddress(match[1]);
  const street = normaliseAddress(match[2]);
  const wholeAddress = normaliseAddress(job.job_address);
  const sameStreet = results.filter(item => Number(item.Type) === 4 && item.PropertyID &&
    normaliseAddress(`${item.StreetNumber ?? ''}${item.StreetAlpha ?? ''}`) === number &&
    normaliseAddress(item.Street ?? item.StreetName) === street);
  const sameLocality = sameStreet.filter(item => item.Suburb
    ? wholeAddress.includes(normaliseAddress(item.Suburb))
    : item.City && wholeAddress.includes(normaliseAddress(item.City)));
  const candidates = sameLocality.length ? sameLocality :
    sameStreet.filter(item => !item.Suburb && !item.City);
  return candidates.length === 1 ? candidates[0] : null;
}

export function consentEvents(timeline) {
  return (Array.isArray(timeline?.events) ? timeline.events : [])
    .filter(item => ['consent', 'building_consent', 'resource_consent'].includes(String(item.key).toLowerCase()))
    .map(item => {
      const data = item.data ?? {};
      return {
        kind: String(data.consent_type ?? data.category ?? data.consent_category ?? item.key ?? '').trim(),
        number: String(data.consent_id ?? data.consent_number ?? data.bc_number ??
          data.application_number ?? item.source_id ?? '').trim(),
        date: String(data.occured_on ?? item.date ?? '').trim(),
        action: [data.action ?? data.type, data.status ?? data.decision_status]
          .filter(Boolean).map(String).join(' · ').trim(),
        description: String(data.description ?? data.consent_description ?? '').trim(),
      };
    });
}

export function consentIdentity(event) {
  const number = event.number.toLowerCase().replace(/[^a-z0-9]+/g, '');
  const basis = number ? `number:${number}` :
    `fallback:${event.date}|${event.action.toLowerCase()}|${event.description.toLowerCase()}`;
  return createHash('sha256').update(basis).digest('hex');
}

export function isIssued(event) {
  return /\b(issued|approved|granted)\b/i.test(event.action);
}

export function latestConsentEvents(events) {
  const byIdentity = new Map();
  for (const event of events) {
    const identity = consentIdentity(event);
    const current = byIdentity.get(identity);
    const eventTime = Date.parse(event.date) || 0;
    const currentTime = current ? Date.parse(current.date) || 0 : -1;
    if (!current || eventTime > currentTime ||
      (eventTime === currentTime && isIssued(event) && !isIssued(current))) {
      byIdentity.set(identity, event);
    }
  }
  return [...byIdentity.values()];
}

export function classifyEvent(event, existing, isFirstCheck) {
  if (existing?.decision === 'ignored' || existing?.decision === 'confirmed') return existing.decision;
  if (existing?.decision === 'needs_review') return 'needs_review';
  if (isFirstCheck) return 'baseline';
  if (existing?.decision === 'baseline') {
    return !existing.was_issued && isIssued(event) ? 'needs_review' : 'baseline';
  }
  return 'needs_review';
}

export function jobPage(rawSize, rawPage, total) {
  const size = [5, 10, 20, 50].includes(Number(rawSize)) ? Number(rawSize) : 5;
  const pages = Math.max(1, Math.ceil(total / size));
  const requested = /^\d+$/.test(rawPage ?? '') ? Number(rawPage) : 1;
  const page = Math.min(Math.max(requested, 1), pages);
  return { size, pages, page, offset: (page - 1) * size };
}
