// End-to-end engine smoke test against the real 3-month dataset.
//
// Run: npx tsx scripts/test-user-data.ts
// Verifies the full dynamic path — parse → correlate → anomalies → risk — and
// prints every correlation so a regression in any single detector is visible.

import { readFileSync } from 'fs';
import { parseAllSources } from '../src/lib/csv.ts';
import { correlateAll } from '../src/lib/correlate.ts';
import { detectAnomalies } from '../src/lib/anomaly.ts';
import { computeRisk, deriveRiskSignals } from '../src/lib/risk.ts';

const DIR = 'C:/Users/Ankush Sharma/OneDrive/Desktop/anti ide/3 month data';
const read = (f: string) => readFileSync(`${DIR}/${f}`, 'utf8');

const parsed = parseAllSources({
  cdr: read('heavy_dense_cdr_3months.csv'),
  ipdr: read('heavy_dense_ip_logs_3months.csv'),
  bank: read('heavy_dense_bank_transactions_3months.csv'),
  social: read('heavy_dense_social_media_3months.csv'),
});

console.log('=== PARSE ===');
console.log(`CDR ${parsed.cdr.length} | IPDR ${parsed.ipdr.length} | Bank ${parsed.bank.length} | Social ${parsed.social.length}`);

// Timestamp integrity — the single most load-bearing invariant in the engine.
const bad = [
  ...parsed.cdr.map((r) => r.timestamp),
  ...parsed.ipdr.map((r) => r.timestamp),
  ...parsed.bank.map((r) => r.timestamp),
  ...parsed.social.map((r) => r.timestamp),
].filter((t) => Number.isNaN(Date.parse(t)));
console.log(`Unparseable timestamps: ${bad.length}${bad.length ? ` — e.g. ${JSON.stringify(bad[0])}` : ' ✓'}`);
console.log('Sample stamps:', parsed.cdr[0]?.timestamp, '|', parsed.bank[0]?.timestamp, '|', parsed.social[0]?.timestamp);

const crypto = { events: [], matched: false, source: 'none' as any };
const correlations = correlateAll(parsed, crypto as any);
const anomalies = detectAnomalies(parsed, crypto as any, '');
const signals = deriveRiskSignals(parsed);
const risk = computeRisk(correlations, anomalies, signals);

console.log(`\n=== CORRELATIONS (${correlations.length}) ===`);
for (const c of correlations) {
  console.log(`\n[${c.risk} ${c.confidence}%] ${c.pair} — ${c.title}`);
  console.log(`  ${c.finding}`);
}

console.log(`\n=== ANOMALIES (${anomalies.count}) ===`);
console.log(`unusualHour=${anomalies.unusualHour} impossibleTravel=${anomalies.impossibleTravel} ofacHit=${anomalies.ofacHit}`);

// Group by type: a flat first-8 slice is dominated by whichever detector is noisiest,
// which hides a silently-dead detector behind 700 off-hours rows.
const byType = new Map<string, { n: number; first: string; severity: string }>();
for (const a of anomalies.anomalies) {
  const hit = byType.get(a.type);
  if (hit) hit.n++;
  else byType.set(a.type, { n: 1, first: a.detail, severity: a.severity });
}
for (const [type, v] of [...byType].sort((a, b) => b[1].n - a[1].n)) {
  console.log(`  ${String(v.n).padStart(4)}× [${v.severity}] ${type}`);
  console.log(`        e.g. ${v.first}`);
}

console.log(`\n=== RISK ===`);
console.log(`Signals: value=₹${signals.totalValue.toLocaleString('en-IN')} crypto=${signals.cryptoCredit} graveyard=${signals.graveyardActivity}`);
console.log(`Score ${risk.score}/100 → ${risk.level}`);
for (const b of risk.breakdown) console.log(`  +${b.points}  ${b.label}`);
