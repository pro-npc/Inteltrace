// Local document store — SQLite via the Node builtin `node:sqlite`.
//
// Drop-in replacement for the former Firestore REST client: same six operations
// (getDoc / setDoc / addDoc / deleteDoc / patchDoc / queryCollection) over the same
// `collection/docId` path strings, so every caller is unchanged.
//
// Why SQLite rather than the hosted database:
//   - Case data never leaves the machine. No OAuth token to mint, no network hop.
//   - No daily read/write quota, so the corpus can be scanned freely for the
//     population-level models in ml/.
//   - Real indexes. The Firestore client could not order by `createdAt` because that
//     field was inside the encrypted payload, so the dashboard fetched 100 documents
//     and sorted them in memory. Indexed columns are extracted here instead.
//
// Sensitive fields are still AES-GCM encrypted at rest exactly as before; only the
// indexable metadata is stored as queryable columns.

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname, isAbsolute, join } from 'node:path';
import { encryptPayload, decryptPayload } from './encryption';

// ─────────────────────────────────────────────────────────────────────────────
// Connection
// ─────────────────────────────────────────────────────────────────────────────

let db: DatabaseSync | null = null;

function resolveDbPath(env: Env): string {
  const dir = env.DATA_DIR?.trim() || 'data';
  const base = isAbsolute(dir) ? dir : join(process.cwd(), dir);
  return join(base, 'inteltrace.db');
}

function connect(env: Env): DatabaseSync {
  if (db) return db;

  const file = resolveDbPath(env);
  mkdirSync(dirname(file), { recursive: true });

  const handle = new DatabaseSync(file);

  // WAL keeps readers from blocking on the analyze write path, and NORMAL sync is
  // the right durability/throughput trade for a single-operator local tool.
  handle.exec('PRAGMA journal_mode = WAL');
  handle.exec('PRAGMA synchronous = NORMAL');
  handle.exec('PRAGMA foreign_keys = ON');

  handle.exec(`
    CREATE TABLE IF NOT EXISTS docs (
      collection      TEXT NOT NULL,
      id              TEXT NOT NULL,
      -- Plaintext indexable metadata, mirrored into columns for querying.
      created_at      TEXT,
      suspect         TEXT,
      risk            TEXT,
      score           INTEGER,
      status          TEXT,
      anomalies_count INTEGER,
      -- Full document: metadata in the clear, everything sensitive inside
      -- the encryptedPayload field when ENCRYPTION_KEY is set.
      data            TEXT NOT NULL,
      PRIMARY KEY (collection, id)
    )
  `);
  handle.exec('CREATE INDEX IF NOT EXISTS idx_docs_created ON docs (collection, created_at DESC)');
  handle.exec('CREATE INDEX IF NOT EXISTS idx_docs_status  ON docs (collection, status)');
  handle.exec('CREATE INDEX IF NOT EXISTS idx_docs_score   ON docs (collection, score DESC)');

  db = handle;
  return handle;
}

/** Close the handle. Used by scripts and tests; the server keeps it open. */
export function closeStore(): void {
  db?.close();
  db = null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Path helpers
// ─────────────────────────────────────────────────────────────────────────────

function splitPath(path: string): { collection: string; id: string } {
  const parts = path.split('/').filter(Boolean);
  if (parts.length < 2) throw new Error(`Invalid document path: ${path}`);
  // `cases_v2/CASE-2024-0892` → collection `cases_v2`, id `CASE-2024-0892`.
  // Deeper paths collapse their trailing segments into the id, which keeps the
  // single-table schema while preserving uniqueness.
  return { collection: parts[0], id: parts.slice(1).join('/') };
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption split
// ─────────────────────────────────────────────────────────────────────────────

// Kept as plaintext so indexes and ordering work. Everything else is encrypted.
const INDEXABLE_FIELDS = new Set([
  'caseId', 'createdAt', 'suspect', 'date', 'sources', 'risk', 'score',
  'status', 'anomaliesCount', 'sourceCounts',
  // Model provenance. Plaintext so a case can be located by the engine version that
  // produced it without decrypting every row — required when a pattern pack or
  // calibrator is revised and prior scores must be re-verified.
  'engineVersion', 'patternPackVersion', 'calibratorVersion',
]);

function splitForEncryption(data: Record<string, unknown>): {
  metadata: Record<string, unknown>;
  sensitive: Record<string, unknown>;
} {
  const metadata: Record<string, unknown> = {};
  const sensitive: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    if (v === undefined) continue;
    if (INDEXABLE_FIELDS.has(k)) metadata[k] = v;
    else sensitive[k] = v;
  }
  return { metadata, sensitive };
}

/** Collections stored in the clear (aggregate counters hold no case content). */
function isPlaintextCollection(collection: string): boolean {
  return collection === 'stats';
}

async function encodeForStorage(
  env: Env,
  collection: string,
  data: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!env.ENCRYPTION_KEY || isPlaintextCollection(collection)) return data;
  const { metadata, sensitive } = splitForEncryption(data);
  return { ...metadata, encryptedPayload: await encryptPayload(sensitive, env.ENCRYPTION_KEY) };
}

async function decodeFromStorage(
  env: Env,
  raw: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!env.ENCRYPTION_KEY || typeof raw.encryptedPayload !== 'string') return raw;
  try {
    const dec = await decryptPayload(raw.encryptedPayload, env.ENCRYPTION_KEY);
    if (dec && typeof dec === 'object') {
      const { encryptedPayload: _drop, ...metadata } = raw;
      return { ...(dec as Record<string, unknown>), ...metadata };
    }
  } catch {
    /* Undecryptable row (wrong key / corrupt): fall through and return metadata only
       rather than dropping the document entirely, so the case stays visible. */
  }
  return raw;
}

// ─────────────────────────────────────────────────────────────────────────────
// Indexed column extraction
// ─────────────────────────────────────────────────────────────────────────────

function str(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 ? v : null;
}
function int(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null;
}

interface IndexedColumns {
  created_at: string | null;
  suspect: string | null;
  risk: string | null;
  score: number | null;
  status: string | null;
  anomalies_count: number | null;
}

function indexColumns(data: Record<string, unknown>): IndexedColumns {
  return {
    created_at: str(data.createdAt),
    suspect: str(data.suspect) ?? str((data.suspectInfo as any)?.name),
    risk: str(data.risk),
    score: int(data.score),
    status: str(data.status),
    anomalies_count: int(data.anomaliesCount),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Operations
// ─────────────────────────────────────────────────────────────────────────────

export async function getDoc(env: Env, path: string): Promise<Record<string, unknown> | null> {
  const { collection, id } = splitPath(path);
  const row = connect(env)
    .prepare('SELECT data FROM docs WHERE collection = ? AND id = ?')
    .get(collection, id) as { data: string } | undefined;
  if (!row) return null;

  const out = await decodeFromStorage(env, JSON.parse(row.data));
  out._name = `${collection}/${id}`;
  return out;
}

export async function setDoc(env: Env, path: string, data: Record<string, unknown>): Promise<void> {
  const { collection, id } = splitPath(path);
  const stored = await encodeForStorage(env, collection, data);
  const cols = indexColumns(data);

  connect(env)
    .prepare(
      `INSERT INTO docs (collection, id, created_at, suspect, risk, score, status, anomalies_count, data)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (collection, id) DO UPDATE SET
         created_at      = excluded.created_at,
         suspect         = excluded.suspect,
         risk            = excluded.risk,
         score           = excluded.score,
         status          = excluded.status,
         anomalies_count = excluded.anomalies_count,
         data            = excluded.data`,
    )
    .run(
      collection, id,
      cols.created_at, cols.suspect, cols.risk, cols.score, cols.status, cols.anomalies_count,
      JSON.stringify(stored),
    );
}

export async function addDoc(
  env: Env,
  collection: string,
  data: Record<string, unknown>,
): Promise<string> {
  // Time-ordered id so natural key order matches insertion order.
  const id = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 10)}`;
  await setDoc(env, `${collection}/${id}`, data);
  return id;
}

export async function deleteDoc(env: Env, path: string): Promise<void> {
  const { collection, id } = splitPath(path);
  connect(env).prepare('DELETE FROM docs WHERE collection = ? AND id = ?').run(collection, id);
}

/**
 * Update specific fields on an existing document, leaving the rest — including the
 * encrypted payload — untouched.
 *
 * Only plaintext metadata fields can be patched. Patching a field that lives inside
 * `encryptedPayload` would require decrypting and re-encrypting the whole document,
 * which is a read-modify-write the callers do not expect; such a request throws
 * rather than silently discarding the update.
 */
export async function patchDoc(
  env: Env,
  path: string,
  data: Record<string, unknown>,
  fieldPaths: string[],
): Promise<void> {
  const { collection, id } = splitPath(path);
  const handle = connect(env);

  const row = handle
    .prepare('SELECT data FROM docs WHERE collection = ? AND id = ?')
    .get(collection, id) as { data: string } | undefined;
  if (!row) throw new Error(`patchDoc ${path} failed: document not found`);

  const encrypted = Boolean(env.ENCRYPTION_KEY) && !isPlaintextCollection(collection);
  if (encrypted) {
    const offLimits = fieldPaths.filter((f) => !INDEXABLE_FIELDS.has(f));
    if (offLimits.length > 0) {
      throw new Error(
        `patchDoc ${path} failed: ${offLimits.join(', ')} live inside the encrypted payload and cannot be patched in place`,
      );
    }
  }

  const stored = JSON.parse(row.data) as Record<string, unknown>;
  for (const field of fieldPaths) {
    if (field in data) stored[field] = data[field];
  }

  // Recompute indexed columns from the merged plaintext metadata.
  const cols = indexColumns(stored);
  handle
    .prepare(
      `UPDATE docs SET created_at = ?, suspect = ?, risk = ?, score = ?, status = ?,
                       anomalies_count = ?, data = ?
       WHERE collection = ? AND id = ?`,
    )
    .run(
      cols.created_at, cols.suspect, cols.risk, cols.score, cols.status, cols.anomalies_count,
      JSON.stringify(stored), collection, id,
    );
}

export interface QueryOptions {
  orderByField?: string;
  orderDir?: 'ASCENDING' | 'DESCENDING';
  limit?: number;
}

// Only these may reach the ORDER BY clause — never interpolate a caller-supplied
// field name into SQL.
const ORDERABLE: Record<string, string> = {
  createdAt: 'created_at',
  suspect: 'suspect',
  risk: 'risk',
  score: 'score',
  status: 'status',
  anomaliesCount: 'anomalies_count',
};

export async function queryCollection(
  env: Env,
  collectionId: string,
  opts: QueryOptions = {},
): Promise<Record<string, unknown>[]> {
  const column = opts.orderByField ? ORDERABLE[opts.orderByField] : 'created_at';
  const dir = opts.orderDir === 'ASCENDING' ? 'ASC' : 'DESC';

  let sql = `SELECT id, data FROM docs WHERE collection = ?`;
  // NULLs last so documents missing the sort key never displace real values.
  if (column) sql += ` ORDER BY (${column} IS NULL), ${column} ${dir}`;
  const params: unknown[] = [collectionId];
  if (opts.limit && opts.limit > 0) {
    sql += ' LIMIT ?';
    params.push(opts.limit);
  }

  const rows = connect(env).prepare(sql).all(...(params as any[])) as Array<{
    id: string;
    data: string;
  }>;

  const out: Record<string, unknown>[] = [];
  for (const r of rows) {
    const doc = await decodeFromStorage(env, JSON.parse(r.data));
    doc._name = `${collectionId}/${r.id}`;
    out.push(doc);
  }
  return out;
}

/** Row count in a collection, without decrypting anything. */
export function countCollection(env: Env, collectionId: string): number {
  const row = connect(env)
    .prepare('SELECT COUNT(*) AS n FROM docs WHERE collection = ?')
    .get(collectionId) as { n: number } | undefined;
  return row?.n ?? 0;
}

/** Store health for the /api/health endpoint. */
export function storeHealth(env: Env): { ok: boolean; path: string; cases: number } {
  try {
    return { ok: true, path: resolveDbPath(env), cases: countCollection(env, 'cases_v2') };
  } catch {
    return { ok: false, path: resolveDbPath(env), cases: 0 };
  }
}
