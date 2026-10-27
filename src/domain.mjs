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
    .filter(item => String(item.key).toLowerCase() === 'consent')
    .map(item => {
      const data = item.data ?? {};
      return {
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

function csvCells(line) {
  const cells = [];
  let current = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    if (char === '"' && quoted && line[i + 1] === '"') { current += '"'; i++; }
    else if (char === '"') quoted = !quoted;
    else if (char === ',' && !quoted) { cells.push(current.trim()); current = ''; }
    else current += char;
  }
  cells.push(current.trim());
  return cells;
}

export function parseJobNumbers(raw) {
  const lines = String(raw).replace(/^\uFEFF/, '').split(/\r?\n/).filter(Boolean);
  if (lines.length === 0) return [];
  const rows = lines.map(csvCells);
  const headerIndex = rows[0].findIndex(cell => /^(?:job\s*(?:number|no|id)|generated_job_id)$/i.test(cell));
  const index = headerIndex >= 0 ? headerIndex : 0;
  const data = headerIndex >= 0 ? rows.slice(1) : rows;
  return [...new Set(data.map(row => row[index] ?? '').filter(number => /^[A-Za-z0-9-]{1,30}$/.test(number)))];
}

export function jobPage(rawSize, rawPage, total) {
  const size = [5, 10, 20, 50].includes(Number(rawSize)) ? Number(rawSize) : 5;
  const pages = Math.max(1, Math.ceil(total / size));
  const requested = /^\d+$/.test(rawPage ?? '') ? Number(rawPage) : 1;
  const page = Math.min(Math.max(requested, 1), pages);
  return { size, pages, page, offset: (page - 1) * size };
}
