// Offline verification harness (not shipped): runs the real ingestion engine
// against the four bundled sample CSVs and asserts CASE-2024-0892 reproduces
// exactly. Bundled with esbuild → node. Run: npm run verify:golden (see below).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { parseAllSources } from '../src/lib/csv';
import { resolveCrypto, computeCryptoMatch } from '../src/lib/crypto-apis';
import { correlateAll } from '../src/lib/correlate';
import { detectAnomalies } from '../src/lib/anomaly';
import { computeRisk } from '../src/lib/risk';
import { buildGoldenCaseDocument } from '../src/lib/viewmodel';
import { matchesGoldenCase } from '../src/lib/fixtures/canonicalCase';

const here = dirname(fileURLToPath(import.meta.url));
const samples = join(here, '..', 'public', 'samples');
const read = (f: string) => readFileSync(join(samples, f), 'utf8');

const WALLET = '0x71C7656EC7ab88b098defB751B7401B5f6d8976F';

let failures = 0;
const ok = (label: string, cond: boolean, got?: unknown) => {
  if (cond) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${got !== undefined ? `  (got: ${JSON.stringify(got)})` : ''}`);
  }
};

async function main() {
  const files = {
    cdr: read('cdr_arjun_verma_202403.csv'),
    ipdr: read('ipdr_arjun_verma_202403.csv'),
    bank: read('bank_hdfc_4821_202403.csv'),
    social: read('social_arjun_verma_202403.csv'),
  };
  const parsed = parseAllSources(files);

  console.log('\n── parse ──');
  ok('cdr rows parsed', parsed.cdr.length >= 4, parsed.cdr.length);
  ok('ipdr rows parsed', parsed.ipdr.length === 3, parsed.ipdr.length);
  ok('bank rows parsed', parsed.bank.length === 4, parsed.bank.length);
  ok('social rows parsed', parsed.social.length === 3, parsed.social.length);

  console.log('\n── golden signature recognition ──');
  ok('matchesGoldenCase(wallet + ₹2,19,450 WazirX credit)', matchesGoldenCase({ wallet: WALLET, bank: parsed.bank }));
  ok('rejects on wrong wallet', !matchesGoldenCase({ wallet: '0xdeadbeef', bank: parsed.bank }));

  console.log('\n── crypto match (independent recompute) ──');
  const credit = parsed.bank.find((b) => b.type === 'CREDIT' && /wazirx/i.test(b.description));
  ok('WazirX credit present', !!credit, credit?.amount);
  const actualFiat = credit?.amount ?? 0;
  const m = computeCryptoMatch(0.0312, 7086600, parsed.bank, '2024-03-15T00:00:00Z', 'WazirX');
  ok('expected fiat = ₹2,19,510', m.expectedFiat === 219510, m.expectedFiat);
  ok('actual credit = ₹2,19,450', Math.round(m.actualFiat || actualFiat) === 219450, actualFiat);
  ok('variance = 0.03%', m.variance === 0.03, m.variance);
  ok('within tolerance (matched)', m.matched === true);

  const crypto = await resolveCrypto(WALLET, parsed.bank, 'WazirX');
  ok('resolveCrypto source = fixture (offline-safe)', crypto.source === 'fixture', crypto.source);
  ok('resolveCrypto matched', crypto.matched === true);
  ok('resolved expectedFiat = 219510', crypto.events[0]?.expectedFiat === 219510, crypto.events[0]?.expectedFiat);
  ok('resolved variance = 0.03', crypto.events[0]?.variance === 0.03, crypto.events[0]?.variance);

  console.log('\n── engine independently detects the six correlations ──');
  const correlations = correlateAll(parsed, crypto);
  ok('6 correlations detected', correlations.length === 6, correlations.map((c) => c.pair));
  ok('has Blockchain ↔ Bank', correlations.some((c) => c.pair === 'Blockchain ↔ Bank'));
  ok('has CDR ↔ Social (alibi)', correlations.some((c) => c.pair === 'CDR ↔ Social Media'));
  ok('has CDR ↔ CDR (co-suspect)', correlations.some((c) => c.pair === 'CDR ↔ CDR'));

  const anomalies = detectAnomalies(parsed, crypto, WALLET);
  const dynRisk = computeRisk(correlations, anomalies);
  console.log(`     dynamic engine risk = ${dynRisk.score} / ${dynRisk.level}`);
  ok('dynamic risk = 87', dynRisk.score === 87, dynRisk.score);
  ok('dynamic level = CRITICAL', dynRisk.level === 'CRITICAL', dynRisk.level);

  console.log('\n── golden case document (authored narrative + real hashes) ──');
  const evidenceHashes = Object.entries(files).map(([k, v]) => ({
    filename: `${k}.csv`,
    sha256: sha256(v),
    sizeBytes: Buffer.byteLength(v),
    source: k.toUpperCase(),
  }));
  const doc = buildGoldenCaseDocument(new Date().toISOString(), evidenceHashes, parsed);
  ok('caseId = CASE-2024-0892', doc.caseId === 'CASE-2024-0892', doc.caseId);
  ok('score = 87', doc.score === 87, doc.score);
  ok('suspect level = CRITICAL', doc.suspectInfo.riskLevel === 'CRITICAL', doc.suspectInfo.riskLevel);
  ok('list badge = HIGH', doc.risk === 'HIGH', doc.risk);
  ok('6 correlations in doc', doc.correlations.length === 6, doc.correlations.length);
  const confs = (doc.correlations as Array<{ confidence: number }>).map((c) => c.confidence);
  ok('confidences = 94/96/89/97/91/78', JSON.stringify(confs) === JSON.stringify([94, 96, 89, 97, 91, 78]), confs);
  ok('anomaliesCount = 9', doc.anomaliesCount === 9, doc.anomaliesCount);
  ok('crypto expected 219510', (doc.cryptoEvents[0] as { expectedFiat: number }).expectedFiat === 219510);
  ok('crypto actual 219450', (doc.cryptoEvents[0] as { actualFiat: number }).actualFiat === 219450);
  ok('crypto variance 0.03', (doc.cryptoEvents[0] as { variance: number }).variance === 0.03);
  ok('4 real evidence hashes', doc.evidenceHashes.length === 4, doc.evidenceHashes.length);
  ok('hashes are 64-hex SHA-256', doc.evidenceHashes.every((h) => /^[0-9a-f]{64}$/.test(h.sha256)));
  console.log('     §65B hashes:');
  for (const h of doc.evidenceHashes) console.log(`       ${h.source.padEnd(6)} ${h.sha256}`);

  console.log(`\n${failures === 0 ? '✅ ALL CHECKS PASSED' : `❌ ${failures} CHECK(S) FAILED`}\n`);
  process.exit(failures === 0 ? 0 : 1);
}

// Node crypto for the harness only (the Worker uses Web Crypto).
import { createHash } from 'node:crypto';
function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
