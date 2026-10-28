import { latestConsentEvents } from './domain.mjs';

const start = '[BC CHECK]';
const end = '[/BC CHECK]';
const checkedDatePattern = '\\d{2} [A-Za-z]{3} \\d{4}';
const statusPattern = new RegExp(`^(?:NO BC|BC - [^|]{1,80}) - ${checkedDatePattern}$`);

export function checkedDate(now = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-NZ', {
    timeZone: 'Pacific/Auckland', day: '2-digit', month: 'short', year: 'numeric',
  }).formatToParts(now).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
  return `${parts.day} ${parts.month} ${parts.year}`;
}

export function bcStatus(events, now = new Date()) {
  return bcAssessment(events, now).status;
}

export function bcAssessment(events, now = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-NZ', { timeZone: 'Pacific/Auckland',
    year: 'numeric', month: '2-digit', day: '2-digit' }).formatToParts(now)
    .filter(part => part.type !== 'literal').map(part => [part.type, Number(part.value)]));
  const today = new Date(Date.UTC(parts.year, parts.month - 1, parts.day));
  const cutoff = new Date(today);
  cutoff.setUTCFullYear(cutoff.getUTCFullYear() - 3);
  const buildingConsents = latestConsentEvents(events).filter(event => {
    const evidence = [event.kind, event.number, event.action, event.description].filter(Boolean).join(' ').replaceAll('_', ' ');
    const bc = /\b(building consent|building permit)\b|\bBC(?:[-\s/:]*\d+|\b)/i.test(evidence);
    const rc = /\b(resource consent|planning consent)\b|\bRC(?:[-\s/:]*\d+|\b)/i.test(evidence);
    const date = new Date(String(event.date).slice(0, 10));
    return bc && !rc && Number.isFinite(date.getTime()) && date <= today;
  }).sort((a, b) => Date.parse(b.date) - Date.parse(a.date));
  const recent = buildingConsents.find(event => new Date(String(event.date).slice(0, 10)) >= cutoff);
  const older = buildingConsents.find(event => new Date(String(event.date).slice(0, 10)) < cutoff);
  return {
    status: recent
      ? `BC - ${recent.number || 'Number unavailable'} - ${checkedDate(now)}`
      : `NO BC - ${checkedDate(now)}`,
    older,
  };
}

export function mergeBcStatus(existing, status) {
  let text = String(existing ?? '').trim();
  if (text.includes(start) !== text.includes(end)) return null;
  while (text.includes(start)) {
    const first = text.indexOf(start);
    const last = text.indexOf(end, first + start.length);
    if (last < 0) return null;
    text = `${text.slice(0, first).trimEnd().replace(/\s*\|\s*$/, '')} ${text.slice(last + end.length).trimStart().replace(/^\|\s*/, '')}`.trim();
  }
  text = text.replace(/\s+\|\s+(?:NO BC|BC - [^|]{1,80}) - \d{2} [A-Za-z]{3} \d{4}$/, '').trim();
  if (statusPattern.test(text)) text = '';
  return [text, status].filter(Boolean).join(' | ');
}
