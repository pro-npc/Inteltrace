// Store smoke test — exercises every operation the app relies on against a
// throwaway database, including the encryption round-trip.
//
//   npx tsx scripts/verify-store.ts
//
// Run after any change to src/lib/store.ts. A silent regression here loses case
// data, and unlike a rendering bug it is not visible in the UI until too late.

import { rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  getDoc,
  setDoc,
  addDoc,
  deleteDoc,
  patchDoc,
  queryCollection,
  countCollection,
  storeHealth,
  closeStore,
} from '../src/lib/store';

let failures = 0;

function check(label: string, cond: boolean, detail = ''): void {
  if (cond) {
    console.log(`  PASS  ${label}`);
  } else {
    failures++;
    console.log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

const dir = mkdtempSync(join(tmpdir(), 'inteltrace-store-'));

const env = {
  SESSION_SECRET: 'test-secret',
  // 64 hex chars, same shape as a real key. Test-only.
  ENCRYPTION_KEY: 'a'.repeat(64),
  DATA_DIR: dir,
  GEMINI_API_KEY: '',
  ETHERSCAN_API_KEY: '',
} as Env;

async function main() {
  console.log('── set / get round-trip with encryption ──');

  const doc = {
    caseId: 'CASE-2026-00001',
    createdAt: '2026-09-19T10:00:00.000Z',
    suspect: 'Test Suspect',
    risk: 'CRITICAL',
    score: 87,
    status: 'ACTIVE',
    anomaliesCount: 9,
    // Sensitive: must survive the encrypt/decrypt round-trip.
    correlations: [{ pair: 'Blockchain ↔ Bank', confidence: 94 }],
    suspectInfo: { name: 'Test Suspect', phone: '+91-98765-43210' },
  };

  await setDoc(env, 'cases_v2/CASE-2026-00001', doc);
  const read = await getDoc(env, 'cases_v2/CASE-2026-00001');

  check('document returned', read !== null);
  check('plaintext metadata intact', read?.score === 87);
  check('encrypted field decrypted', Array.isArray(read?.correlations));
  check(
    'nested encrypted value intact',
    (read?.suspectInfo as any)?.phone === '+91-98765-43210',
  );
  check('_name stamped', read?._name === 'cases_v2/CASE-2026-00001');

  console.log('\n── sensitive fields are not readable on disk ──');
  const { DatabaseSync } = await import('node:sqlite');
  const raw = new DatabaseSync(join(dir, 'inteltrace.db'), { readOnly: true });
  const stored = raw
    .prepare('SELECT data, score, status, created_at FROM docs WHERE id = ?')
    .get('CASE-2026-00001') as any;
  raw.close();

  check('phone number absent from stored row', !stored.data.includes('98765-43210'));
  check('encryptedPayload present', stored.data.includes('encryptedPayload'));
  check('score extracted to its column', stored.score === 87);
  check('created_at extracted to its column', stored.created_at === '2026-09-19T10:00:00.000Z');

  console.log('\n── patch ──');
  await patchDoc(env, 'cases_v2/CASE-2026-00001', { status: 'CLOSED' }, ['status']);
  const patched = await getDoc(env, 'cases_v2/CASE-2026-00001');
  check('status updated', patched?.status === 'CLOSED');
  check('encrypted payload survived the patch', Array.isArray(patched?.correlations));

  let threw = false;
  try {
    await patchDoc(env, 'cases_v2/CASE-2026-00001', { correlations: [] }, ['correlations']);
  } catch {
    threw = true;
  }
  check('patching an encrypted field is refused', threw);

  console.log('\n── ordering ──');
  await setDoc(env, 'cases_v2/CASE-2026-00002', {
    caseId: 'CASE-2026-00002',
    createdAt: '2026-09-20T10:00:00.000Z',
    score: 40,
    status: 'ACTIVE',
  });
  // No createdAt: must sort last rather than displacing a real value.
  await setDoc(env, 'cases_v2/CASE-2026-00003', { caseId: 'CASE-2026-00003', score: 10 });

  const listed = await queryCollection(env, 'cases_v2', { limit: 10 });
  check('three documents listed', listed.length === 3, `got ${listed.length}`);
  check('newest first', listed[0]?.caseId === 'CASE-2026-00002', String(listed[0]?.caseId));
  check('null createdAt sorts last', listed[2]?.caseId === 'CASE-2026-00003', String(listed[2]?.caseId));

  const byScore = await queryCollection(env, 'cases_v2', {
    orderByField: 'score',
    orderDir: 'ASCENDING',
  });
  check('ordered by score ascending', byScore[0]?.score === 10, String(byScore[0]?.score));

  // An unknown sort key must not reach the SQL text.
  const injected = await queryCollection(env, 'cases_v2', {
    orderByField: "score; DROP TABLE docs; --",
  });
  check('unknown order key is ignored, not interpolated', injected.length === 3);

  console.log('\n── add / delete / count ──');
  const auditId = await addDoc(env, 'audit', { event: 'test', ts: new Date().toISOString() });
  check('addDoc returned an id', typeof auditId === 'string' && auditId.length > 0);
  check('audit row counted', countCollection(env, 'audit') === 1);

  await deleteDoc(env, `audit/${auditId}`);
  check('audit row deleted', countCollection(env, 'audit') === 0);
  check('missing document reads as null', (await getDoc(env, 'audit/nope')) === null);

  console.log('\n── stats collection stays plaintext ──');
  await setDoc(env, 'stats/global', { activeCases: 2, reportsGenerated: 1 });
  const statsRaw = new DatabaseSync(join(dir, 'inteltrace.db'), { readOnly: true });
  const statsRow = statsRaw
    .prepare("SELECT data FROM docs WHERE collection = 'stats' AND id = 'global'")
    .get() as any;
  statsRaw.close();
  check('counters readable without a key', statsRow.data.includes('"activeCases":2'));

  console.log('\n── health ──');
  const health = storeHealth(env);
  check('health ok', health.ok);
  check('health counts cases', health.cases === 3, String(health.cases));

  closeStore();

  console.log(
    failures === 0 ? '\n✅ ALL CHECKS PASSED' : `\n❌ ${failures} CHECK(S) FAILED`,
  );
  rmSync(dir, { recursive: true, force: true });
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  rmSync(dir, { recursive: true, force: true });
  process.exit(1);
});
