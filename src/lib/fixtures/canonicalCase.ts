// Canonical view-model for the curated golden case CASE-2024-0892 (Arjun Verma).
//
// The analysis engine is fully dynamic, but the curated sample dataset carries an
// authored analyst narrative — the exact correlation confidences (94/96/89/97/91/78)
// and their prose, the merged timeline, the network graph, and the overview
// findings/actions — that cannot be re-derived from raw CSV rows alone. When the
// ingestion pipeline recognises the curated dataset, it computes everything
// computable (crypto match math, real SHA-256 evidence hashes, the 87/CRITICAL
// risk score) and attaches this authored narrative so the Results page reproduces
// exactly. Arbitrary uploads take the fully dynamic path instead (see viewmodel.ts).
//
// Arrays are re-exported from the single source of truth in src/data so the
// backend and any remaining static references never drift.

import {
  suspectInfo,
  cdrEvents,
  ipdrEvents,
  bankEvents,
  socialEvents,
  cryptoEvents,
  timelineEvents,
  correlations,
  networkNodes,
  networkEdges,
} from '../../data/mockInvestigation';

export const CANONICAL_CASE_ID = 'CASE-2024-0892';

export {
  suspectInfo,
  cdrEvents,
  ipdrEvents,
  bankEvents,
  socialEvents,
  cryptoEvents,
  timelineEvents,
  correlations,
  networkNodes,
  networkEdges,
};

// Overview finding cards (3-column grid on the Results Overview tab).
export const findings = [
  { title: 'Call-Triggered Transfer',     risk: 'HIGH',     source: 'CDR ↔ Bank',       conf: 94, star: false, desc: 'Calls to Rohan Sharma preceded 3 financial transfers within 10-minute windows. Pattern recurrence <1.8% random probability.' },
  { title: 'Crypto-to-Fiat Conversion',   risk: 'CRITICAL', source: 'Blockchain ↔ Bank', conf: 96, star: true,  desc: '0.0312 BTC → ₹2,19,450 via WazirX. Amount variance 0.03% — within exchange tolerance. Algorithmically confirmed.' },
  { title: 'Anonymous Account Exposed',   risk: 'HIGH',     source: 'IPDR ↔ Social',     conf: 89, star: false, desc: '@av_investments linked to VPN IP 45.32.87.211. Same IP identified in IPDR session on suspect\'s registered IMEI.' },
  { title: 'Location Alibi Refuted',      risk: 'CRITICAL', source: 'CDR ↔ Social',      conf: 97, star: false, desc: 'Tower ping (Panaji, Goa 23:41) + Instagram geotag (Candolim 23:30) place the suspect in Goa on the night of March 15 — directly refuting the sworn Bandra, Mumbai alibi.' },
  { title: 'Device Transaction Linked',   risk: 'MEDIUM',   source: 'IPDR ↔ Bank',       conf: 91, star: false, desc: 'Samsung S23 (IMEI 35-XXXXXX-1) confirmed as transaction device for all 3 banking sessions via IP fingerprinting.' },
  { title: 'Co-Ordination Network',       risk: 'MEDIUM',   source: 'CDR ↔ CDR',         conf: 78, star: false, desc: 'Both A. Verma & Vikram Shah called relay #90012 within 8 minutes on 3 dates — <0.3% coincidence probability.' },
];

// Recommended investigative actions (Overview tab).
export const actions = [
  'Data preservation order to WazirX under PMLA §12A — 48hr SLA',
  'Court order for call recordings: +91-97543-XXXXX via Indian Telegraph Act §5',
  'Tower dump request — GOA-PNJ-0091, March 15 23:00–24:00',
  'HDFC Bank Section 91 CrPC notice — full session logs for HDFC-4821',
  'MLAT request — trace ₹5L RTGS origin from Singapore (Mar 01)',
  'Expand investigation: Vikram Shah (+91-84930-XXXXX) as co-conspirator',
  'FIU-IND check: wallet 0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
];

// The behavioural anomalies the curated case surfaces. Each one is the anomaly the
// dynamic detector (src/lib/anomaly.ts) raises for the corresponding curated row, so
// the golden narrative and a live run describe the same case in the same vocabulary.
// Enumerated rather than asserted as a bare number: the Results page shows this list,
// and a count with nothing behind it is exactly the "flags but never says what"
// failure the engine is meant to avoid.
export const anomalies: import('../anomaly').Anomaly[] = [
  { id: 'anom-1', type: 'off-hours-activity',         severity: 'MEDIUM', source: 'CDR',        timestamp: '2024-03-15T23:41:00', detail: 'Call activity at 23:41 (tower GOA-PNJ-0091, Panaji) within the 22:00–05:00 window — 302 s to +91-84930-XXXXX.' },
  { id: 'anom-2', type: 'off-hours-activity',         severity: 'MEDIUM', source: 'IPDR',       timestamp: '2024-03-15T02:14:00', detail: 'Internet session to tor-exit.node at 02:14 — off-hours, running until 03:40.' },
  { id: 'anom-3', type: 'off-hours-activity',         severity: 'LOW',    source: 'Social',     timestamp: '2024-03-15T23:30:00', detail: 'Post from @arjun_real_life at 23:30 — off-hours, geotagged Goa.' },
  { id: 'anom-4', type: 'burst-transaction',          severity: 'HIGH',   source: 'Bank',       timestamp: '2024-03-15T11:10:00', detail: 'Two transactions within 2 minutes at 11:10 — ₹2,19,450 credit followed by ₹15,000 debit. Rapid layering.' },
  { id: 'anom-5', type: 'opaque-large-credit',        severity: 'HIGH',   source: 'Bank',       timestamp: '2024-03-01T09:00:00', detail: '₹5,00,000 credit from an opaque origin ("RTGS - Unknown Origin - Singapore Acct").' },
  { id: 'anom-6', type: 'anonymization-usage',        severity: 'HIGH',   source: 'IPDR',       timestamp: '2024-03-15T02:14:00', detail: 'TOR/VPN indicator on OnePlus 11 (tor-exit.node, 890.2 MB) at 02:14 — IMEI distinct from the suspect\'s registered handset.' },
  { id: 'anom-7', type: 'geolocation-conflict',       severity: 'MEDIUM', source: 'Social',                                       detail: '@arjun_real_life tagged in mumbai and goa on the same day (2024-03-15).' },
  { id: 'anom-8', type: 'rapid-liquidation',          severity: 'HIGH',   source: 'Blockchain', timestamp: '2024-03-15T10:58:00', detail: '0.0312 BTC received at 10:58 and settled to fiat at 11:10 — 12-minute hold, no custody period.' },
  // Deliberately not 'impossible-travel': ~580 km in ~9.2 h is ~63 km/h, entirely
  // drivable. It is still anomalous movement, and it is what places the device back
  // in Mumbai the next morning.
  { id: 'anom-9', type: 'interstate-overnight-movement', severity: 'MEDIUM', source: 'CDR',     timestamp: '2024-03-16T08:55:00', detail: 'Device moved GOA-PNJ-0091 (23:41, Panaji) → BOM-ANW-2201 (08:55, Andheri West): ~580 km overnight, ~9.2 h.' },
];

// The curated case surfaces 9 behavioural anomalies (matches the history row).
// Derived from the list so the two can never drift apart.
export const CANONICAL_ANOMALY_COUNT = anomalies.length;

// The wallet the curated case is built around (lowercased for comparison).
export const CANONICAL_WALLET = '0x71c7656ec7ab88b098defb751b7401b5f6d8976f';

export interface GoldenSignatureInput {
  wallet?: string | null;
  bank?: Array<{ type?: string; amount?: number; description?: string }>;
}

/**
 * Recognise the curated dataset. True when the analysed wallet is the curated
 * suspect wallet AND the bank statement contains the signature ₹2,19,450 WazirX
 * credit. Both must hold, so an unrelated upload never masquerades as the golden
 * case.
 */
export function matchesGoldenCase(input: GoldenSignatureInput): boolean {
  const wallet = (input.wallet || '').trim().toLowerCase();
  if (wallet !== CANONICAL_WALLET) return false;
  const bank = input.bank || [];
  return bank.some(
    (b) =>
      (b.type || '').toUpperCase() === 'CREDIT' &&
      Math.round(Number(b.amount)) === 219450 &&
      /wazirx/i.test(b.description || ''),
  );
}
