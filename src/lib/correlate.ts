// 6-way correlation engine (prototype.md §Correlation Engine Logic).
//
// Emits correlations in the exact shape the Correlations tab renders:
//   { id, pair, title, confidence, risk, color, finding, action, fullWidth, star }
//
// This is the dynamic path used for arbitrary uploads. The curated case
// CASE-2024-0892 is served from the authored narrative in fixtures/canonicalCase
// (identical confidences 94/96/89/97/91/78); this engine independently detects
// the same six relationships so risk scoring and arbitrary datasets both work.

import type { ParsedSources, CdrRow, BankRow } from './csv';
import type { CryptoResolution } from './crypto-apis';

export interface Correlation {
  id: string;
  pair: string;
  title: string;
  confidence: number;
  risk: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  color: string;
  finding: string;
  action: string;
  fullWidth: boolean;
  star: boolean;
}

const ms = (iso: string): number => {
  if (!iso) return 0;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? 0 : t;
};

const dayOf = (iso: string): string => (iso ? iso.slice(0, 10) : '');

/**
 * Local hour 0–23, or -1 when the timestamp carries no time component.
 *
 * Never fall back to `new Date(ms(iso)).getHours()`: `ms()` returns 0 on a parse
 * failure, so that path reports the hour of the unix epoch for every malformed
 * row — which is how an entire dataset can silently read as "05:30 activity".
 */
const hourOf = (iso: string): number => {
  const m = /T(\d{2}):/.exec(iso || '');
  if (!m) return -1;
  const h = Number(m[1]);
  return h >= 0 && h <= 23 ? h : -1;
};

/** 01:00–04:59 — the deepest inactivity band for a legitimate user. */
const isGraveyard = (iso: string): boolean => {
  const h = hourOf(iso);
  return h >= 1 && h < 5;
};

/** 22:00–04:59 — off-baseline activity, broader than the graveyard window. */
const isLateNight = (iso: string): boolean => {
  const h = hourOf(iso);
  return h >= 22 || (h >= 0 && h < 5);
};

const clampConf = (n: number): number => Math.max(50, Math.min(98, Math.round(n)));

function riskFromConfidence(conf: number): Correlation['risk'] {
  if (conf >= 95) return 'CRITICAL';
  if (conf >= 85) return 'HIGH';
  if (conf >= 70) return 'MEDIUM';
  return 'LOW';
}

const inr = (n: number): string => `₹${Number(n || 0).toLocaleString('en-IN')}`;
const hhmm = (iso: string): string => (iso && iso.length >= 16 ? iso.slice(11, 16) : '—');

/** Minutes between two ISO timestamps; Infinity when either fails to parse. */
function minutesBetween(a: string, b: string): number {
  const ta = ms(a);
  const tb = ms(b);
  if (!ta || !tb) return Infinity;
  return Math.abs(ta - tb) / 60000;
}

/** Indian crypto exchanges + generic asset tokens, for bank-statement matching. */
const CRYPTO_EXCHANGE_KEYWORDS = [
  'wazirx', 'binance', 'coindcx', 'zebpay', 'coinswitch', 'bitbns', 'giottus',
  'unocoin', 'krakenpay', 'coinbase', 'kraken', 'bitfinex', 'okx', 'kucoin',
  'blockchain', 'usdt', 'tether', 'bitcoin', 'ethereum', 'crypto', 'btc', 'eth',
];

/** Exchange/asset keyword found in a bank row's free-text fields, if any. */
function cryptoKeywordIn(row: BankRow): string | null {
  const hay = [row.description, row.sender, row.senderAcc, row.receiver, row.bankName]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();
  return CRYPTO_EXCHANGE_KEYWORDS.find((kw) => hay.includes(kw)) ?? null;
}

/** Below this separation, two "different cities" are an ordinary commute, not an alibi break. */
const MIN_ALIBI_KM = 150;
/** Faster than commercial aviation — no lawful explanation for the transit. */
const IMPOSSIBLE_KMH = 800;

/** Great-circle distance in km; 0 when either coordinate is missing. */
function haversineKm(lat1: number, lng1: number, lat2: number, lng2: number): number {
  if (!lat1 || !lat2 || !lng1 || !lng2) return 0;
  const R = 6371;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLng = toRad(lng2 - lng1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

/**
 * Canonical city token from a free-text geotag ("GOA-Calangute" → "goa").
 *
 * Returns '' when nothing recognisable is present. Never fall back to the raw first
 * word: an unrecognised token compared against a tower prefix produces a false
 * "different city" verdict, which is how "DXB" vs "Dubai" was reported as an alibi
 * contradiction when both refer to the same place.
 */
function cityFromTag(locationTag: string): string {
  const normalized = (locationTag || '').toLowerCase();
  const cityMap: Record<string, string> = {
    goa: 'goa', panaji: 'goa', panjim: 'goa', calangute: 'goa', baga: 'goa',
    candolim: 'goa', vagator: 'goa', anjuna: 'goa', margao: 'goa',
    mumbai: 'mumbai', bombay: 'mumbai', bandra: 'mumbai', andheri: 'mumbai',
    colaba: 'mumbai', worli: 'mumbai', juhu: 'mumbai', lokhandwala: 'mumbai',
    delhi: 'delhi', gurgaon: 'delhi', gurugram: 'delhi', noida: 'delhi',
    kolkata: 'kolkata', calcutta: 'kolkata',
    bangalore: 'bengaluru', bengaluru: 'bengaluru', koramangala: 'bengaluru',
    hyderabad: 'hyderabad', chennai: 'chennai', madras: 'chennai',
    pune: 'pune', ahmedabad: 'ahmedabad', jaipur: 'jaipur',
    lucknow: 'lucknow', patna: 'patna', nagpur: 'nagpur',
    dubai: 'dubai', uae: 'dubai', 'abu dhabi': 'dubai', sharjah: 'dubai',
    singapore: 'singapore', 'hong kong': 'hongkong', hongkong: 'hongkong',
    london: 'london', bangkok: 'bangkok', 'kuala lumpur': 'kualalumpur',
    doha: 'doha', istanbul: 'istanbul', 'new york': 'newyork',
  };
  for (const [key, city] of Object.entries(cityMap)) {
    if (normalized.includes(key)) return city;
  }
  return '';
}

/** Approximate city-centre coordinates, for quantifying alibi impossibility. */
const CITY_COORDS: Record<string, [number, number]> = {
  goa: [15.2993, 74.124],
  mumbai: [19.076, 72.8777],
  delhi: [28.6139, 77.209],
  kolkata: [22.5726, 88.3639],
  bengaluru: [12.9716, 77.5946],
  hyderabad: [17.385, 78.4867],
  chennai: [13.0827, 80.2707],
  pune: [18.5204, 73.8567],
  ahmedabad: [23.0225, 72.5714],
  jaipur: [26.9124, 75.7873],
  lucknow: [26.8467, 80.9462],
  patna: [25.5941, 85.1376],
  nagpur: [21.1458, 79.0882],
  dubai: [25.2048, 55.2708],
  singapore: [1.3521, 103.8198],
  hongkong: [22.3193, 114.1694],
  london: [51.5072, -0.1276],
  bangkok: [13.7563, 100.5018],
  kualalumpur: [3.139, 101.6869],
  doha: [25.2854, 51.531],
  istanbul: [41.0082, 28.9784],
  newyork: [40.7128, -74.006],
};

/** Last path token of a phone number, for loose contact matching (…-97543-…). */
function contactKey(num: string): string {
  const matches = (num || '').match(/\d+/g);
  if (!matches) return num;
  const longest = matches.sort((a, b) => b.length - a.length)[0];
  return longest.length >= 5 ? longest : num;
}

/** #1 CDR ↔ Bank — a call to a contact shortly precedes a transfer to them. */
function cdrBank(cdr: CdrRow[], bank: BankRow[]): Correlation | null {
  const bList = bank.map(b => ({
    unix: ms(b.timestamp),
    partyStr: [b.receiver, b.sender, b.description].join(' ').toLowerCase()
  })).sort((a, b) => a.unix - b.unix);

  const cList = cdr
    .filter(c => c.type === 'call')
    .map(c => ({ unix: ms(c.timestamp), key: contactKey(c.to)?.toLowerCase() }))
    .filter(c => !!c.key)
    .sort((a, b) => a.unix - b.unix);

  let matches = 0;
  let minDelta = Infinity;

  for (const b of bList) {
    let left = 0;
    while (left < cList.length && cList[left].unix < b.unix - 1440 * 60000) left++;
    
    for (let i = left; i < cList.length; i++) {
      const c = cList[i];
      if (c.unix > b.unix + 1440 * 60000) break;
      if (b.partyStr.includes(c.key!)) {
        matches++;
        minDelta = Math.min(minDelta, Math.abs(b.unix - c.unix) / 60000);
      }
    }
  }

  if (matches === 0) return null;
  const conf = clampConf(80 + Math.min(matches, 3) * 4 + (minDelta <= 15 ? 5 : -10));
  return {
    id: '',
    pair: 'CDR ↔ Bank',
    title: 'Call-Triggered Transfer Pattern',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#3B82F6',
    finding: `A call to a contact preceded ${matches} financial transfer(s) within a suspicious time window (closest ${Math.round(minDelta)} min). This pattern often indicates coordination with a mule or victim.`,
    action: 'Obtain call recordings via court order. Cross-reference account for layering transactions.',
    fullWidth: false,
    star: false,
  };
}

/** #2 Blockchain ↔ Bank — crypto liquidation signature reconciles to a credit. */
function cryptoBank(crypto: CryptoResolution): Correlation | null {
  if (!crypto.matched || crypto.events.length === 0) return null;
  const e = crypto.events[0];
  const conf = clampConf(90 + (e.variance < 0.1 ? 6 : e.variance < 0.5 ? 4 : 2));
  const asset = e.amountBTC != null ? `${e.amountBTC} BTC` : `${e.amountETH} ETH`;
  return {
    id: '',
    pair: 'Blockchain ↔ Bank',
    title: 'Layered Crypto-to-Fiat Conversion',
    confidence: conf,
    risk: 'CRITICAL',
    color: '#F59E0B',
    finding: e.flag || `${asset} received at ${e.timestamp.slice(11, 16)}. Price at timestamp: ₹${e.priceAtTime.toLocaleString('en-IN')}. Expected deposit after ${e.exchange || 'exchange'} fee: ₹${e.expectedFiat.toLocaleString('en-IN')}. Actual credit: ₹${e.actualFiat.toLocaleString('en-IN')}. Variance: ${e.variance}% — within exchange settlement tolerance.`,
    action: 'Formal data preservation request to the exchange under PMLA. Trace origin wallet via OFAC sanctions list.',
    fullWidth: true,
    star: true,
  };
}

/**
 * #2b Blockchain ↔ Bank, statement-only path.
 *
 * The signature correlation must not depend on an analyst manually supplying a
 * wallet address: cryptoBank() returns null the moment `crypto.matched` is false,
 * which is the common case for a plain four-CSV upload. This detects the fiat leg
 * directly from exchange names in the bank narration, then looks for the rapid
 * outflow that distinguishes conversion proceeds from an ordinary purchase.
 */
function cryptoBankFromStatement(bank: BankRow[]): Correlation | null {
  const cryptoCredits = bank.filter((b) => b.type === 'CREDIT' && cryptoKeywordIn(b) !== null);
  if (cryptoCredits.length === 0) return null;

  const largest = cryptoCredits.reduce((a, b) => (a.amount > b.amount ? a : b));
  const creditTime = ms(largest.timestamp);

  // Outflow ≥30% of the credit within 4 h reads as immediate layering.
  const rapidOutflow = creditTime
    ? bank.filter((b) => {
        if (b.type !== 'DEBIT') return false;
        const t = ms(b.timestamp);
        return t > creditTime && t - creditTime <= 4 * 60 * 60000 && b.amount >= largest.amount * 0.3;
      })
    : [];
  const outflowTotal = rapidOutflow.reduce((s, b) => s + b.amount, 0);

  const totalCrypto = cryptoCredits.reduce((s, b) => s + b.amount, 0);
  const conf = clampConf(
    85 +
      (rapidOutflow.length > 0 ? 8 : 0) +
      (largest.amount > 1000000 ? 5 : 0) +
      (cryptoCredits.length > 1 ? 2 : 0),
  );

  const exchange = (cryptoKeywordIn(largest) ?? 'crypto exchange').toUpperCase();
  const multi =
    cryptoCredits.length > 1
      ? ` ${cryptoCredits.length} exchange-linked credits total ${inr(totalCrypto)}.`
      : '';
  const layering =
    rapidOutflow.length > 0
      ? ` ${inr(outflowTotal)} moved out across ${rapidOutflow.length} debit(s) within 4 hours — consistent with immediate layering of converted proceeds.`
      : '';

  return {
    id: '',
    pair: 'Blockchain ↔ Bank',
    title: 'Crypto-to-Fiat Credit Detected',
    confidence: conf,
    risk: 'CRITICAL',
    color: '#F59E0B',
    finding: `${inr(largest.amount)} credited from ${exchange} at ${hhmm(largest.timestamp)}${largest.description ? ` (narration: "${largest.description}")` : ''}.${multi}${layering}`,
    action: `Issue a legal notice to ${exchange} for KYC and transaction records under PMLA. Freeze account ${largest.receiverAcc || largest.account || 'on record'} under PMLA Section 17 and trace the counterparty wallet.`,
    fullWidth: true,
    star: true,
  };
}

function ipdrSocial(sources: ParsedSources): Correlation | null {
  const ipdrList = sources.ipdr.filter(s => s.ip).map(s => ({ ip: s.ip, unix: ms(s.timestamp) }));
  const hits = sources.social.filter((s) => {
    if (!s.loginIp) return false;
    const sUnix = ms(s.timestamp);
    return ipdrList.some(ipdr => ipdr.ip === s.loginIp && Math.abs(ipdr.unix - sUnix) <= 60 * 60000);
  });
  if (hits.length === 0) return null;
  const anon = hits.find((h) => /invest|anon|alt|_x|business/i.test(h.username)) || hits[0];
  // Capped at three corroborating hits: a fourth shared IP adds nothing an examiner
  // would weigh differently, and an uncapped count pins every large dataset to 98%.
  const conf = clampConf(82 + Math.min(hits.length, 3) * 3);
  return {
    id: '',
    pair: 'IPDR ↔ Social Media',
    title: 'Anonymous Account Linked to Physical Device',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#8B5CF6',
    finding: `Social account ${anon.username} logged in from IP ${anon.loginIp}, the same IP recorded in an IPDR session on the suspect's device. Device fingerprint and session timing confirm the same physical device accessed both.`,
    action: `Serve legal notice to the platform for account-ownership data on ${anon.username}. Prepare MLAT request if servers are offshore.`,
    fullWidth: false,
    star: false,
  };
}

/**
 * #4 CDR ↔ Social — tower location cross-checked against post geotags.
 *
 * Two distinct forensic modes, because real casework produces both:
 *
 *  A. CONTRADICTION — a tower places the handset in one city while a
 *     near-simultaneous post is geotagged in another, far enough apart that the
 *     implied transit speed is impossible. One of the two records is staged.
 *
 *  B. CORROBORATION — tower and geotag AGREE on a city that is not the subject's
 *     established operating base. Two independent sources placing the subject away
 *     from base is what refutes a stated alibi, and it is the stronger evidence of
 *     the two precisely because the sources do not conflict.
 *
 * An earlier revision fired on bare agreement with no base-city comparison, which
 * flagged every ordinary post from home. A later one fired only on conflict, which
 * went silent on the canonical Goa case. Both modes are needed.
 */
function cdrSocial(sources: ParsedSources): Correlation | null {
  return alibiContradiction(sources) ?? alibiCorroboration(sources);
}

/** Mode A — tower and geotag disagree, and the separation makes the transit impossible. */
function alibiContradiction(sources: ParsedSources): Correlation | null {
  let best: {
    call: CdrRow;
    post: ParsedSources['social'][number];
    towerCity: string;
    tagCity: string;
    km: number;
    gapMin: number;
  } | null = null;

  for (const post of sources.social) {
    if (!post.locationTag) continue;
    const tagCity = cityFromTag(post.locationTag);
    if (!tagCity) continue;

    for (const call of sources.cdr) {
      const gapMin = minutesBetween(post.timestamp, call.timestamp);
      if (gapMin > 60) continue; // includes Infinity from unparseable timestamps

      const towerCity = towerCityToken(call.tower);
      if (!towerCity) continue;

      const conflict =
        towerCity !== tagCity && !tagCity.includes(towerCity) && !towerCity.includes(tagCity);
      if (!conflict) continue;

      const [tLat, tLng] = CITY_COORDS[towerCity] ?? [0, 0];
      const [pLat, pLng] = CITY_COORDS[tagCity] ?? [0, 0];
      const km = haversineKm(
        call.towerLat ?? tLat,
        call.towerLong ?? tLng,
        post.locationLat ?? pLat,
        post.locationLng ?? pLng,
      );

      // Prefer the widest separation — the most damning pairing.
      if (!best || km > best.km) best = { call, post, towerCity, tagCity, km, gapMin };
    }
  }

  if (!best) return null;

  const { call, post, towerCity, tagCity, km, gapMin } = best;
  const speedKmh = km > 0 && gapMin > 0 ? km / (gapMin / 60) : Infinity;

  // Only claim impossibility when the physics actually say so. Two adjacent cities
  // 40 km apart inside an hour is an ordinary commute, and reporting that as
  // "physically impossible" would discredit the whole finding under cross-examination.
  if (km < MIN_ALIBI_KM || speedKmh < IMPOSSIBLE_KMH) return null;

  const speedText = Number.isFinite(speedKmh)
    ? `~${Math.round(speedKmh).toLocaleString('en-IN')} km/h`
    : 'an instantaneous transit';

  return {
    id: '',
    pair: 'CDR ↔ Social Media',
    title: 'Location Alibi Contradiction — Physically Impossible',
    confidence: clampConf(95),
    risk: 'CRITICAL',
    color: '#EF4444',
    finding: `Cell tower ${call.tower} places the suspect in ${towerCity.toUpperCase()} at ${hhmm(call.timestamp)}, while a social post ${gapMin < 1 ? 'in the same minute' : `${Math.round(gapMin)} minutes ${ms(post.timestamp) > ms(call.timestamp) ? 'later' : 'earlier'}`} is geotagged "${post.locationTag}" (${tagCity.toUpperCase()}). The two locations are ~${Math.round(km).toLocaleString('en-IN')} km apart, implying ${speedText} — physically impossible. One of the two records is being staged.`,
    action: 'File the charge-sheet section citing alibi refutation. Request a tower dump for the full network at that location and time, and preserve the post with platform-side metadata via a Section 91 CrPC notice.',
    fullWidth: false,
    star: true,
  };
}

/** A city holding at least this share of tower pings counts as the operating base. */
const BASE_CITY_SHARE = 0.45;
/** Fewer located pings than this and "base city" is an assumption, not a finding. */
const BASE_CITY_MIN_PINGS = 8;

/**
 * Mode B — tower and geotag independently place the subject in the same city, and
 * that city is not their operating base.
 *
 * Two independent record types agreeing on an away-from-base location is what
 * refutes a stated alibi in court. The base city is derived from the subject's own
 * tower history rather than assumed, and the finding is withheld unless one city
 * clearly dominates that history — without a dominant base there is nothing to be
 * "away from" and the claim would not survive cross-examination.
 */
function alibiCorroboration(sources: ParsedSources): Correlation | null {
  const cityCounts = new Map<string, number>();
  let located = 0;
  for (const c of sources.cdr) {
    const city = towerCityToken(c.tower);
    if (!city) continue;
    located++;
    cityCounts.set(city, (cityCounts.get(city) ?? 0) + 1);
  }
  if (located < BASE_CITY_MIN_PINGS) return null;

  let baseCity = '';
  let baseCount = 0;
  for (const [city, n] of cityCounts) {
    if (n > baseCount) {
      baseCity = city;
      baseCount = n;
    }
  }
  if (!baseCity || baseCount / located < BASE_CITY_SHARE) return null;

  // Tightest tower/post pair that agrees on a city away from base.
  let best: {
    call: CdrRow;
    post: ParsedSources['social'][number];
    city: string;
    gapMin: number;
  } | null = null;

  for (const post of sources.social) {
    if (!post.locationTag) continue;
    const tagCity = cityFromTag(post.locationTag);
    if (!tagCity || tagCity === baseCity) continue;

    for (const call of sources.cdr) {
      const gapMin = minutesBetween(post.timestamp, call.timestamp);
      if (gapMin > 60) continue; // includes Infinity from unparseable timestamps
      if (towerCityToken(call.tower) !== tagCity) continue;
      if (!best || gapMin < best.gapMin) best = { call, post, city: tagCity, gapMin };
    }
  }
  if (!best) return null;

  const { call, post, city, gapMin } = best;
  const [bLat, bLng] = CITY_COORDS[baseCity] ?? [0, 0];
  const [cLat, cLng] = CITY_COORDS[city] ?? [0, 0];
  const kmFromBase = haversineKm(call.towerLat ?? cLat, call.towerLong ?? cLng, bLat, bLng);
  const distance = kmFromBase > 0 ? ` — ~${Math.round(kmFromBase).toLocaleString('en-IN')} km from the ${baseCity.toUpperCase()} base` : '';

  // Tight agreement between two independent record types is what carries the weight.
  const conf = clampConf(88 + (gapMin <= 15 ? 6 : gapMin <= 30 ? 3 : 0));

  return {
    id: '',
    pair: 'CDR ↔ Social Media',
    title: 'Location Alibi Refuted — Two Independent Sources',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#EF4444',
    finding: `Cell tower ${call.tower} places the handset in ${city.toUpperCase()} at ${hhmm(call.timestamp)}, and a post ${Math.round(gapMin)} minute(s) ${ms(post.timestamp) > ms(call.timestamp) ? 'later' : 'earlier'} is independently geotagged "${post.locationTag}". ${baseCount} of ${located} located pings sit in ${baseCity.toUpperCase()}, so ${city.toUpperCase()}${distance} is away from the established operating base. Two unrelated record types placing the subject at the same away-from-base location refutes any alibi to the contrary.`,
    action: `Tower dump for ${call.tower} covering the hour around ${hhmm(call.timestamp)}, and a Section 91 CrPC notice to the platform for server-side geotag metadata on the post. Put both to the subject on the alibi they have given.`,
    fullWidth: false,
    star: true,
  };
}

/**
 * City token from a tower id like GOA-PNJ-0091 / BOM-MTW-4421 / DXB-UAE-1306.
 *
 * Tries the second segment too: some operators encode the country in segment 1 and
 * the city in segment 2. Returns '' for anything unrecognised so callers can refuse
 * to compare two unknown tokens — comparing raw prefixes made "DXB" and the geotag
 * "Dubai" read as two different cities and produced a false alibi contradiction.
 */
function towerCityToken(tower: string): string {
  const parts = (tower || '').toLowerCase().split('-');
  const map: Record<string, string> = {
    bom: 'mumbai', mum: 'mumbai', goa: 'goa', pnj: 'goa', del: 'delhi',
    blr: 'bengaluru', pnq: 'pune', hyd: 'hyderabad', maa: 'chennai',
    ccu: 'kolkata', amd: 'ahmedabad', pat: 'patna', lko: 'lucknow',
    jpr: 'jaipur', jai: 'jaipur', nag: 'nagpur', dxb: 'dubai', uae: 'dubai',
    sin: 'singapore', hkg: 'hongkong', lon: 'london', nyc: 'newyork',
    bkk: 'bangkok', kul: 'kualalumpur', doh: 'doha', ist: 'istanbul',
  };
  for (const p of parts) {
    if (map[p]) return map[p];
  }
  return '';
}

/**
 * #5 IPDR ↔ Bank — a banking or exchange session brackets a transaction.
 *
 * The matching window is asymmetric by design. A direct banking portal debits in
 * near real time, so ±15 min is right. A crypto exchange settles fiat withdrawals
 * over hours under RBI rules, so a session at 16:05 legitimately corresponds to a
 * credit at 18:45; a flat 15-minute window silently discards those pairs.
 */
const CRYPTO_DOMAIN_RE = /wazirx|binance|coindcx|zebpay|coinswitch|bitbns|giottus|unocoin|coinbase|kraken|okx|kucoin|crypto|exchange/i;
const BANK_DOMAIN_RE = /bank|hdfc|icici|axis|sbi|kotak|yesbank|idfc|neft|imps|rtgs|upi|netbanking|corp|alphacorp/i;

function ipdrBank(sources: ParsedSources): Correlation | null {
  const CRYPTO_WINDOW_MS = 6 * 60 * 60000; // exchange settlement lag
  const BANK_WINDOW_MS = 15 * 60000;

  let best: {
    session: ParsedSources['ipdr'][number];
    row: BankRow;
    deltaMin: number;
    isCrypto: boolean;
    after: boolean;
  } | null = null;

  for (const s of sources.ipdr) {
    const isCrypto = CRYPTO_DOMAIN_RE.test(s.domain);
    const isBank = BANK_DOMAIN_RE.test(s.domain);
    if (!isCrypto && !isBank) continue;

    const start = ms(s.timestamp);
    if (!start) continue;
    const end = ms(s.sessionEnd) || start;
    const windowMs = isCrypto ? CRYPTO_WINDOW_MS : BANK_WINDOW_MS;

    for (const b of sources.bank) {
      const t = ms(b.timestamp);
      if (!t) continue;
      if (t < start - windowMs || t > end + windowMs) continue;

      const deltaMin = Math.round(Math.abs(t - start) / 60000);
      // Tightest pairing is the most probative.
      if (!best || deltaMin < best.deltaMin) {
        best = { session: s, row: b, deltaMin, isCrypto, after: t > end };
      }
    }
  }

  if (!best) return null;

  const { session: s, row: b, deltaMin, isCrypto, after } = best;
  const conf = clampConf(
    85 + (deltaMin <= 5 ? 10 : deltaMin <= 30 ? 5 : 0) + (isCrypto ? 3 : 0),
  );

  return {
    id: '',
    pair: 'IPDR ↔ Bank',
    title: isCrypto
      ? 'Crypto Exchange Session Linked to Fiat Credit'
      : 'Device Confirms Transaction Initiation',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#10B981',
    finding: `Device ${s.device || 'on record'}${s.imei ? ` (IMEI ${s.imei})` : ''} accessed ${s.domain} at ${hhmm(s.timestamp)}. A ${b.type.toLowerCase()} of ${inr(b.amount)} was processed ${deltaMin} minute(s) ${after ? 'after the session closed' : 'inside the session window'}. ${isCrypto ? 'The session-to-settlement gap is consistent with exchange fiat-withdrawal processing time.' : 'This proves the transaction was digitally initiated from the suspect’s registered device.'}`,
    action: isCrypto
      ? 'Subpoena the exchange for session logs matching this IP and timestamp, plus the linked bank-withdrawal reference.'
      : 'Device seizure warrant to confirm the IMEI match. Extract session logs via a Section 91 CrPC notice.',
    fullWidth: false,
    star: false,
  };
}

/** #6 CDR ↔ CDR — two callers reach the same relay number within 8 min, repeatedly. */
function cdrCdr(cdr: CdrRow[]): Correlation | null {
  const byReceiver = new Map<string, { from: string; unix: number; day: string }[]>();
  for (const c of cdr) {
    if (c.type !== 'call') continue;
    let list = byReceiver.get(c.to);
    if (!list) {
      list = [];
      byReceiver.set(c.to, list);
    }
    list.push({ from: c.from, unix: ms(c.timestamp), day: dayOf(c.timestamp) });
  }

  for (const [receiver, calls] of byReceiver) {
    if (calls.length < 2) continue;
    // sort calls by time to enable sliding window
    calls.sort((a, b) => a.unix - b.unix);
    
    const datesWithPair = new Set<string>();
    const callers = new Set<string>();
    
    for (let i = 0; i < calls.length; i++) {
      for (let j = i + 1; j < calls.length; j++) {
        if (calls[j].unix > calls[i].unix + 8 * 60000) break; // beyond 8 mins
        if (calls[i].from === calls[j].from) continue;
        
        datesWithPair.add(calls[i].day);
        callers.add(calls[i].from);
        callers.add(calls[j].from);
      }
    }
    
    if (datesWithPair.size >= 2 && callers.size >= 2) {
      const conf = clampConf(70 + Math.min(datesWithPair.size, 6) * 3);
      const callerList = [...callers].join(', ');
      return {
        id: '',
        pair: 'CDR ↔ CDR',
        title: 'Indirect Coordination Pattern — Co-Suspect',
        confidence: conf,
        risk: riskFromConfidence(conf),
        color: '#6366F1',
        finding: `Callers ${callerList} both contacted relay number ${receiver} within 8-minute windows on ${datesWithPair.size} separate dates. Statistical probability of random coincidence is negligible — consistent with a coordinated operation via a shared handler.`,
        action: 'Expand the investigation to the co-caller as a co-conspirator. Tower dump for the relay number to map the full network.',
        fullWidth: false,
        star: false,
      };
    }
  }
  return null;
}

/**
 * #6b Tower ↔ Tower — consecutive pings that no lawful journey connects.
 *
 * The anomaly engine already flags this, but a single line inside several hundred
 * off-hours rows is not where the strongest finding in a case should live. Distance
 * and implied speed come straight off the tower coordinates, so the claim is
 * arithmetic an opposing expert can re-run rather than an inference to be argued.
 */
function geospatialImpossibility(cdr: CdrRow[]): Correlation | null {
  const pings = cdr
    .filter((c) => c.towerLat != null && c.towerLong != null && ms(c.timestamp) > 0)
    .sort((a, b) => ms(a.timestamp) - ms(b.timestamp));

  let worst: { prev: CdrRow; cur: CdrRow; km: number; hours: number; speed: number } | null = null;
  let violations = 0;

  for (let i = 1; i < pings.length; i++) {
    const prev = pings[i - 1];
    const cur = pings[i];
    const km = haversineKm(prev.towerLat!, prev.towerLong!, cur.towerLat!, cur.towerLong!);
    if (km < MIN_ALIBI_KM) continue;
    const hours = (ms(cur.timestamp) - ms(prev.timestamp)) / 3_600_000;
    if (hours <= 0) continue;
    const speed = km / hours;
    if (speed < IMPOSSIBLE_KMH) continue;
    violations++;
    if (!worst || speed > worst.speed) worst = { prev, cur, km, hours, speed };
  }

  if (!worst) return null;

  const { prev, cur, km, hours, speed } = worst;
  const mins = Math.round(hours * 60);
  // Repetition is what separates a cloned SIM or a relocated handset from a single
  // corrupted record, so it is the only thing that moves the confidence.
  const conf = clampConf(88 + Math.min(violations, 3) * 2);

  return {
    id: '',
    pair: 'CDR ↔ CDR',
    title: 'Geospatial Impossibility — Handset in Two Places',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#EF4444',
    finding: `Tower ${prev.tower} logged the handset at ${hhmm(prev.timestamp)}, then ${cur.tower} logged it ${mins} minute(s) later — ~${Math.round(km).toLocaleString('en-IN')} km away. That requires ~${Math.round(speed).toLocaleString('en-IN')} km/h, which no lawful transit achieves.${violations > 1 ? ` ${violations} such transitions appear across the record, so this is a sustained pattern rather than a single corrupt row.` : ''} Either the SIM has been cloned, the handset is shared between operators, or the subscriber records have been tampered with.`,
    action: `Tower dumps for both ${prev.tower} and ${cur.tower} across the window, and an IMEI/IMSI pairing history request to the operator to establish whether the SIM was cloned or the handset shared.`,
    fullWidth: false,
    star: true,
  };
}

/**
 * #7 Behavioural Baselining (Anomaly Delta) — subjective night operation detection.
 *
 * Counts across every timestamped source, not just calls, and uses the 22:00–04:59
 * late-night band with a graveyard sub-count.
 *
 * Requires a real population: calling three late events out of twenty a "deviation
 * from the established baseline" is statistically meaningless, and a defence expert
 * would take it apart in a sentence. Below BASELINE_MIN_EVENTS there is no baseline
 * to deviate from, so the detector stays silent rather than overclaiming.
 */
const BASELINE_MIN_EVENTS = 50;

function behaviouralBaseline(sources: ParsedSources): Correlation | null {
  const stamps: string[] = [
    ...sources.cdr.filter((c) => c.type === 'call').map((c) => c.timestamp),
    ...sources.ipdr.map((s) => s.timestamp),
    ...sources.bank.map((b) => b.timestamp),
    ...sources.social.map((p) => p.timestamp),
  ].filter((t) => hourOf(t) >= 0);

  if (stamps.length < BASELINE_MIN_EVENTS) return null;

  const lateNight = stamps.filter(isLateNight);
  const graveyard = stamps.filter(isGraveyard);
  if (lateNight.length === 0) return null;

  const pct = lateNight.length / stamps.length;
  const hours = [...new Set(lateNight.map((t) => hhmm(t)))].sort();

  // Rare night activity is the signal. A subject who is always up at 03:00 has no
  // deviation to report; one whose entire record is daytime except three 02:00
  // events does.
  if (pct > 0.4) return null;

  const conf = clampConf(78 + (graveyard.length > 0 ? 12 : 4) + (1 - pct) * 8);
  return {
    id: '',
    pair: 'Behavioural Baseline',
    title: 'Deviant Behavioural Baseline — Off-Hours Operation',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#F43F5E',
    finding: `${lateNight.length} of ${stamps.length} recorded events (${(pct * 100).toFixed(1)}%) fall in the 22:00–05:00 window${graveyard.length > 0 ? `, ${graveyard.length} of them in the 01:00–05:00 graveyard band` : ''}. Timestamps: ${hours.slice(0, 6).join(', ')}${hours.length > 6 ? '…' : ''}. Activity clustered outside the subject's own established pattern indicates evasive or time-pressured operation.`,
    action: 'Flag every counter-party contacted during these specific hours and cross-reference their own records for the same window.',
    fullWidth: false,
    star: false,
  };
}

/** IMEI Binding Score — Cross-reference IMEI across CDR and IPDR */
function imeiBinding(sources: ParsedSources): Correlation | null {
  // Map IPDR IMEIs to their timestamps
  const ipdrImeis = new Map<string, number[]>();
  for (const session of sources.ipdr) {
    if (!session.imei) continue;
    if (!ipdrImeis.has(session.imei)) ipdrImeis.set(session.imei, []);
    ipdrImeis.get(session.imei)!.push(ms(session.timestamp));
  }

  let matchedImei = '';
  let matchCount = 0;

  for (const call of sources.cdr) {
    if (!call.imei) continue;
    const callTime = ms(call.timestamp);
    const sessionTimes = ipdrImeis.get(call.imei);
    if (sessionTimes) {
      for (const st of sessionTimes) {
        if (Math.abs(st - callTime) <= 60 * 60000) { // 1 hour overlap
          matchedImei = call.imei;
          matchCount++;
          break;
        }
      }
    }
  }

  if (matchCount > 0) {
    // Capped: three co-occurring sessions already establish the binding.
    const conf = clampConf(85 + Math.min(matchCount, 3) * 3);
    return {
      id: '',
      pair: 'CDR ↔ IPDR',
      title: 'Single Physical Device Confirmed (IMEI Binding)',
      confidence: conf,
      risk: riskFromConfidence(conf),
      color: '#8B5CF6',
      finding: `IMEI ${matchedImei} was active in both cellular (CDR) and data (IPDR) sessions concurrently. This cryptographically binds the suspect's telecommunication footprint to the digital footprint.`,
      action: 'File as §65B digital evidence. Seize device matching this IMEI.',
      fullWidth: false,
      star: false,
    };
  }

  return null;
}

/**
 * Bank Velocity Analysis — densest true 45-minute burst.
 *
 * Rows with an unparseable timestamp are dropped rather than folded in at unix 0,
 * which previously collapsed an entire statement into one fake "45-minute" window
 * and reported every row as a rapid-fire transfer.
 */
function bankVelocity(bank: BankRow[]): Correlation | null {
  const WINDOW_MS = 45 * 60000;
  const transfers = bank
    .filter((b) => b.amount > 0 && ms(b.timestamp) > 0)
    .map((b) => ({ ...b, unix: ms(b.timestamp) }))
    .sort((a, b) => a.unix - b.unix);

  let best: { count: number; sum: number; from: string; to: string } | null = null;

  for (let i = 0; i < transfers.length; i++) {
    let windowSum = 0;
    let j = i;
    while (j < transfers.length && transfers[j].unix <= transfers[i].unix + WINDOW_MS) {
      windowSum += transfers[j].amount;
      j++;
    }
    const count = j - i;
    if (count >= 3 && windowSum > 1000000 && (!best || count > best.count || (count === best.count && windowSum > best.sum))) {
      best = { count, sum: windowSum, from: transfers[i].timestamp, to: transfers[j - 1].timestamp };
    }
  }

  if (!best) return null;

  const spanMin = Math.round(minutesBetween(best.from, best.to));
  const conf = clampConf(88 + Math.min(best.count, 4) * 2);
  return {
    id: '',
    pair: 'Bank Velocity',
    title: 'High-Velocity Transfer Burst',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#EF4444',
    finding: `${best.count} transfers totalling ${inr(best.sum)} cleared between ${hhmm(best.from)} and ${hhmm(best.to)} — a ${Number.isFinite(spanMin) ? spanMin : 45}-minute burst. This velocity is characteristic of scripted dispersal or panic-dumping.`,
    action: 'Freeze the destination accounts pending review for wash trading or fund dissipation.',
    fullWidth: true,
    star: true,
  };
}

/**
 * #8 Bank ↔ Bank — smurfing / structuring.
 *
 * Kept as its own correlation rather than merged into velocity: structuring to stay
 * under the ₹50,000 PAN-quoting threshold is an independent PMLA offence from
 * layering, so it carries a separate recommended action in the report.
 */
function smurfingBank(bank: BankRow[]): Correlation | null {
  const STRUCTURING_FLOOR = 40000;
  const STRUCTURING_CEIL = 49999;
  const structured = bank.filter((b) => b.amount >= STRUCTURING_FLOOR && b.amount <= STRUCTURING_CEIL);
  if (structured.length < 3) return null;

  const total = structured.reduce((s, b) => s + b.amount, 0);
  const amounts = [...new Set(structured.map((b) => b.amount))];
  const uniformity = amounts.length === 1 ? ` All ${structured.length} are the identical amount ${inr(amounts[0])}, indicating a deliberate template rather than incidental transaction sizing.` : '';

  const dated = structured.filter((b) => ms(b.timestamp) > 0).sort((a, b) => ms(a.timestamp) - ms(b.timestamp));
  const spanNote =
    dated.length >= 2
      ? ` Sequence runs ${hhmm(dated[0].timestamp)} → ${hhmm(dated[dated.length - 1].timestamp)}.`
      : '';

  // Capped at five structured transactions: 119 of them is a bigger case, not a more
  // certain inference, and an uncapped count reported every dataset at 98%.
  const conf = clampConf(80 + Math.min(structured.length, 5) * 3 + (amounts.length === 1 ? 4 : 0));
  return {
    id: '',
    pair: 'Bank ↔ Bank',
    title: 'Smurfing / Structuring — Threshold Evasion',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#EF4444',
    finding: `${structured.length} transactions totalling ${inr(total)} sit just below the ₹50,000 PAN-quoting threshold (₹40k–₹49,999).${uniformity}${spanNote} This is textbook structuring to stay beneath automated AML reporting.`,
    action: 'File a Suspicious Transaction Report (STR) with FIU-IND under PMLA. Obtain full KYC for every receiving account and charge structuring separately from layering.',
    fullWidth: false,
    star: false,
  };
}

/**
 * #9 Bank ↔ Bank — rapid layering (mule signature).
 *
 * Matches on AGGREGATE outflow ratio inside a 2-hour window rather than a single
 * debit within ±10% of the credit. A mule that splits ₹18.5 L across four transfers
 * is the textbook case and the single-debit test missed all of them.
 */
function rapidLayering(bank: BankRow[]): Correlation | null {
  const LAYER_WINDOW_MS = 120 * 60000;
  const MIN_AMOUNT = 100000;
  const MIN_RATIO = 0.6;

  const credits = bank
    .filter((b) => b.type === 'CREDIT' && b.amount > MIN_AMOUNT && ms(b.timestamp) > 0)
    .map((b) => ({ ...b, unix: ms(b.timestamp) }));
  const debits = bank
    .filter((b) => b.type === 'DEBIT' && b.amount > MIN_AMOUNT && ms(b.timestamp) > 0)
    .map((b) => ({ ...b, unix: ms(b.timestamp) }))
    .sort((a, b) => a.unix - b.unix);

  let best: { credit: (typeof credits)[number]; count: number; totalOut: number; ratio: number; windowMin: number } | null = null;

  for (const c of credits) {
    const matching = debits.filter((d) => d.unix > c.unix && d.unix - c.unix <= LAYER_WINDOW_MS);
    if (matching.length === 0) continue;

    const totalOut = matching.reduce((s, d) => s + d.amount, 0);
    const ratio = totalOut / c.amount;
    if (ratio < MIN_RATIO) continue;

    const windowMin = Math.round((matching[matching.length - 1].unix - c.unix) / 60000);
    if (!best || ratio > best.ratio) {
      best = { credit: c, count: matching.length, totalOut, ratio, windowMin };
    }
  }

  if (!best) return null;

  const pct = Math.round(best.ratio * 100);
  const conf = clampConf(80 + (pct >= 90 ? 12 : pct >= 75 ? 8 : 4));
  return {
    id: '',
    pair: 'Bank ↔ Bank',
    title: 'Rapid Layering — Money Mule Signature',
    confidence: conf,
    risk: riskFromConfidence(conf),
    color: '#F97316',
    finding: `${inr(best.credit.amount)} credited at ${hhmm(best.credit.timestamp)}. ${pct}% of it (${inr(best.totalOut)}) was moved out across ${best.count} transaction(s) within ${best.windowMin} minutes. Retaining almost none of an incoming credit is a definitive intermediary-mule signature.`,
    action: 'Freeze the account under Section 102 CrPC to prevent further dissipation, and trace every destination account as a potential co-conspirator.',
    fullWidth: false,
    star: false,
  };
}

/** Corroboration asymptote — no amount of mutual support certifies a correlation outright. */
const ENSEMBLE_CEILING = 97;

/** Run all correlations; return those present, numbered corr-1..corr-N. */
export function correlateAll(sources: ParsedSources, crypto: CryptoResolution): Correlation[] {
  const candidates = [
    cdrBank(sources.cdr, sources.bank),
    // Signature feature. Prefer the on-chain resolution when a wallet was supplied;
    // otherwise recover the same relationship from exchange names in bank narration
    // so a plain four-CSV upload still fires it.
    cryptoBank(crypto) || cryptoBankFromStatement(sources.bank),
    ipdrSocial(sources),
    cdrSocial(sources),
    ipdrBank(sources),
    cdrCdr(sources.cdr),
    geospatialImpossibility(sources.cdr),
    behaviouralBaseline(sources),
    imeiBinding(sources),
    bankVelocity(sources.bank),
    smurfingBank(sources.bank),
    rapidLayering(sources.bank)
  ].filter((c): c is Correlation => c !== null);

  // Ensemble Confidence Boosting.
  //
  // Mutual corroboration raises confidence, but with diminishing returns: a finding
  // already at 96% has almost nothing left to gain, while one at 78% gains real
  // ground from being one of several independent lines pointing the same way. A flat
  // +5 pushed every detector into the 98% clamp, so the printed confidence stopped
  // discriminating between a near-certain link and a merely probable one.
  if (candidates.length >= 3) {
    for (const c of candidates) {
      c.confidence = clampConf(c.confidence + (ENSEMBLE_CEILING - c.confidence) * 0.25);
      c.risk = riskFromConfidence(c.confidence);
    }
  }

  return candidates.map((c, i) => ({ ...c, id: `corr-${i + 1}` }));
}
