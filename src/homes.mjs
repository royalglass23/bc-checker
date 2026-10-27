import { consentEvents, searchStreet, selectExactProperty } from './domain.mjs';

async function homesGet(path) {
  const response = await fetch(`https://gateway.homes.co.nz${path}`, {
    headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`Homes.co.nz returned ${response.status}`);
  return response.json();
}

export async function lookupConsents(job) {
  if (!job.job_address?.trim()) throw new Error('ServiceM8 job has no address');
  const search = await homesGet(`/address/search?Address=${encodeURIComponent(searchStreet(job))}`);
  const match = selectExactProperty(job, Array.isArray(search.Results) ? search.Results : []);
  if (!match) throw new Error('Property address could not be matched uniquely');
  const [property, timeline] = await Promise.all([
    homesGet(`/properties?property_ids=${encodeURIComponent(match.PropertyID)}`),
    homesGet(`/property/${encodeURIComponent(match.PropertyID)}/timeline`),
  ]);
  const card = Array.isArray(property.cards) ? property.cards.find(item =>
    String(item.property_id ?? item.id) === String(match.PropertyID)) : null;
  if (!card?.property_details) throw new Error('Matched property details are unavailable');
  const candidateUrl = new URL(card.url || '/', 'https://homes.co.nz');
  const sourceUrl = candidateUrl.protocol === 'https:' &&
    (candidateUrl.hostname === 'homes.co.nz' || candidateUrl.hostname.endsWith('.homes.co.nz'))
    ? candidateUrl.toString() : 'https://homes.co.nz/';
  return { matchedAddress: String(card.property_details.display_address ?? card.property_details.address ?? ''),
    sourceUrl, events: consentEvents(timeline) };
}
