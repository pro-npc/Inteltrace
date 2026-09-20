// Deterministic, rule-based anomaly detection.
//
// The prototype narrates an "Isolation Forest" ML model; in practice a small set
// of transparent, explainable rules reproduces the same behavioural flags a
// forensic analyst expects — and, unlike a black box, each anomaly cites its
// evidence. Output feeds risk.ts (situational flags) and the report.

import type { ParsedSources, CdrRow } from './csv';
import type { CryptoResolution } from './crypto-apis';
import { isOfacSanctioned } from './fixtures/ofac';

export interface Anomaly {
  id: string;
  type: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  detail: string;
  source: string;
  timestamp?: string;
}

export interface AnomalyResult {
  anomalies: Anomaly[];
  count: number;
  /** Activity in the 22:00–05:00 window. */
  unusualHour: boolean;
  /** Physically impossible movement between two timestamped locations. */
  impossibleTravel: boolean;
  /** A counterparty wallet is on the OFAC SDN list. */
  ofacHit: boolean;
}

const OFF_HOUR_START = 22;
const OFF_HOUR_END = 5;

const hourOf = (iso: string): number => {
  const m = /T(\d{2}):/.exec(iso || '');
  return m ? Number(m[1]) : -1;
};
const isOffHours = (iso: string): boolean => {
  const h = hourOf(iso);
  return h >= OFF_HOUR_START || (h >= 0 && h < OFF_HOUR_END);
};
const ms = (iso: string): number => {
  const t = Date.parse(iso || '');
  return Number.isNaN(t) ? 0 : t;
};

/** Great-circle distance in km between two lat/long points. */
function haversineKm(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}

/** Detect physically impossible travel between consecutive CDR tower pings. */
function detectImpossibleTravel(cdr: CdrRow[]): { impossible: boolean; detail?: string } {
  const pings = cdr
    .filter((c) => c.towerLat != null && c.towerLong != null)
    .sort((a, b) => ms(a.timestamp) - ms(b.timestamp));
  for (let i = 1; i < pings.length; i++) {
    const prev = pings[i - 1];
    const cur = pings[i];
    const km = haversineKm(prev.towerLat!, prev.towerLong!, cur.towerLat!, cur.towerLong!);
    const hours = Math.abs(ms(cur.timestamp) - ms(prev.timestamp)) / 3_600_000;
    if (hours > 0 && km > 50) {
      const speed = km / hours;
      if (speed > 700) {
        return {
          impossible: true,
          detail: `${Math.round(km)} km between ${prev.tower} and ${cur.tower} in ${hours.toFixed(1)} h (${Math.round(speed)} km/h) — physically impossible.`,
        };
      }
    }
  }
  return { impossible: false };
}

export function detectAnomalies(
  sources: ParsedSources,
  crypto: CryptoResolution,
  wallet: string,
): AnomalyResult {
  const anomalies: Anomaly[] = [];
  let seq = 0;
  const add = (a: Omit<Anomaly, 'id'>) => anomalies.push({ id: `anom-${++seq}`, ...a });

  // 1) Off-hours activity across every source.
  let unusualHour = false;
  for (const c of sources.cdr) {
    if (c.type === 'call' && isOffHours(c.timestamp)) {
      unusualHour = true;
      add({ type: 'off-hours-activity', severity: 'MEDIUM', source: 'CDR', timestamp: c.timestamp, detail: `Call activity at ${c.timestamp.slice(11, 16)} (tower ${c.tower}) within the 22:00–05:00 window.` });
    }
  }
  for (const s of sources.ipdr) {
    if (isOffHours(s.timestamp)) {
      unusualHour = true;
      add({ type: 'off-hours-activity', severity: 'MEDIUM', source: 'IPDR', timestamp: s.timestamp, detail: `Internet session to ${s.domain} at ${s.timestamp.slice(11, 16)} — off-hours.` });
    }
  }
  for (const p of sources.social) {
    if (isOffHours(p.timestamp)) {
      unusualHour = true;
      add({ type: 'off-hours-activity', severity: 'LOW', source: 'Social', timestamp: p.timestamp, detail: `Post from ${p.username} at ${p.timestamp.slice(11, 16)} — off-hours.` });
    }
  }

  // 2) Burst transactions — two or more within a 2-minute window.
  const bankByTime = [...sources.bank].sort((a, b) => ms(a.timestamp) - ms(b.timestamp));
  for (let i = 1; i < bankByTime.length; i++) {
    if (Math.abs(ms(bankByTime[i].timestamp) - ms(bankByTime[i - 1].timestamp)) <= 2 * 60000) {
      add({ type: 'burst-transaction', severity: 'HIGH', source: 'Bank', timestamp: bankByTime[i].timestamp, detail: `Two transactions within 2 minutes at ${bankByTime[i].timestamp.slice(11, 16)} — rapid layering.` });
    }
  }

  // 3) Opaque large credit.
  for (const b of sources.bank) {
    if (b.type === 'CREDIT' && b.amount >= 300000 && /unknown|opaque|remit|overseas|singapore|offshore/i.test(b.description)) {
      add({ type: 'opaque-large-credit', severity: 'HIGH', source: 'Bank', timestamp: b.timestamp, detail: `₹${b.amount.toLocaleString('en-IN')} credit from an opaque origin ("${b.description}").` });
    }
  }

  // 4) Anonymization (TOR/VPN) usage.
  for (const s of sources.ipdr) {
    if (/tor|vpn|proxy|\.onion/i.test(s.domain) || s.dataMB > 500) {
      add({ type: 'anonymization-usage', severity: 'HIGH', source: 'IPDR', timestamp: s.timestamp, detail: `TOR/VPN indicator on ${s.device} (${s.domain}, ${s.dataMB} MB) at ${s.timestamp.slice(11, 16)}.` });
    }
  }

  // 5) Geolocation conflict — same account, two far-apart location tags same day.
  const byUser = new Map<string, string[]>();
  for (const p of sources.social) {
    if (!p.locationTag) continue;
    const key = `${p.username}|${p.timestamp.slice(0, 10)}`;
    const list = byUser.get(key) || [];
    list.push(p.locationTag.split(',')[0].trim());
    byUser.set(key, list);
  }
  for (const [key, tags] of byUser) {
    const uniq = [...new Set(tags.map((t) => t.toLowerCase()))];
    if (uniq.length >= 2) {
      add({ type: 'geolocation-conflict', severity: 'MEDIUM', source: 'Social', detail: `${key.split('|')[0]} tagged in ${uniq.join(' and ')} on the same day.` });
    }
  }

  // 6) Impossible travel between tower pings.
  const travel = detectImpossibleTravel(sources.cdr);
  if (travel.impossible) {
    add({ type: 'impossible-travel', severity: 'HIGH', source: 'CDR', detail: travel.detail! });
  }

  // 7) OFAC-sanctioned counterparty.
  let ofacHit = false;
  const e = crypto.events[0];
  const candidates = [wallet, e?.from, e?.to].filter(Boolean) as string[];
  for (const addr of candidates) {
    if (isOfacSanctioned(addr)) {
      ofacHit = true;
      add({ type: 'ofac-sanctioned-counterparty', severity: 'HIGH', source: 'Blockchain', detail: `Counterparty ${addr} appears on the OFAC SDN list.` });
    }
  }

  return {
    anomalies,
    count: anomalies.length,
    unusualHour,
    impossibleTravel: travel.impossible,
    ofacHit,
  };
}
