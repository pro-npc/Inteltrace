// Dynamic case-document smoke test: parse → correlate → anomalies → risk → viewmodel.
//
// Run: npx tsx scripts/test-dynamic.ts
//
// Exercises buildDynamicCaseDocument, which the golden harness does not cover — that
// one builds the authored document instead. Feeds the real sample CSVs through the
// parser rather than the canonicalCase display fixtures: those are view rows shaped
// for the UI and are missing imei/towerLat/towerLong, so handing them to the engine
// typechecked as `any` and silently exercised a shape production never sees.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseAllSources } from '../src/lib/csv.ts';
import { resolveCrypto } from '../src/lib/crypto-apis.ts';
import { correlateAll } from '../src/lib/correlate.ts';
import { detectAnomalies } from '../src/lib/anomaly.ts';
import { computeRisk, deriveRiskSignals } from '../src/lib/risk.ts';
import { buildDynamicCaseDocument } from '../src/lib/viewmodel.ts';
import { CANONICAL_WALLET } from '../src/lib/fixtures/canonicalCase.ts';

const samples = join(dirname(fileURLToPath(import.meta.url)), '..', 'public', 'samples');
const read = (f: string) => readFileSync(join(samples, f), 'utf8');

const parsed = parseAllSources({
  cdr: read('cdr_arjun_verma_202403.csv'),
  ipdr: read('ipdr_arjun_verma_202403.csv'),
  bank: read('bank_hdfc_4821_202403.csv'),
  social: read('social_arjun_verma_202403.csv'),
});

const crypto = await resolveCrypto(CANONICAL_WALLET, parsed.bank, 'WazirX');
const correlations = correlateAll(parsed, crypto);
const anomalies = detectAnomalies(parsed, crypto, CANONICAL_WALLET);
const risk = computeRisk(correlations, anomalies, deriveRiskSignals(parsed));

const doc = buildDynamicCaseDocument({
  caseId: 'CASE-DYNAMIC-TEST',
  createdAt: new Date().toISOString(),
  wallet: CANONICAL_WALLET,
  suspect: { name: 'Arjun Verma' },
  parsed,
  crypto,
  correlations,
  anomalies,
  risk,
  evidenceHashes: [],
});

console.log(`risk         ${doc.score}/100 → ${doc.suspectInfo.riskLevel} (list badge ${doc.risk})`);
console.log(`correlations ${doc.correlations.length}`);
console.log(`anomalies    ${doc.anomaliesCount}`);
console.log(`timeline     ${doc.timelineEvents.length} entries`);

console.log(`\nnetwork      ${doc.networkNodes.length} nodes / ${doc.networkEdges.length} edges`);
for (const n of doc.networkNodes) console.log(`  node  ${n.id}  ${JSON.stringify(n.label ?? '')}`);
for (const e of doc.networkEdges) console.log(`  edge  ${e.from} → ${e.to}  ${JSON.stringify(e.label ?? '')}`);

// An isolated node renders as a dot with nothing attached to it, which is exactly the
// "graph is not linking correlated entities" symptom.
const linked = new Set(doc.networkEdges.flatMap((e) => [e.from, e.to]));
const orphans = doc.networkNodes.filter((n) => !linked.has(n.id));
console.log(`\norphan nodes ${orphans.length}${orphans.length ? `: ${orphans.map((n) => n.id).join(', ')}` : ' ✓'}`);
