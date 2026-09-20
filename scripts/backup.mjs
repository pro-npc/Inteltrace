// Local backup of the case database.
//
// Going local removed the one thing the hosted database gave for free: durable,
// off-machine copies. A single `data/inteltrace.db` on one laptop is one disk
// failure away from losing every case, so this is not optional housekeeping.
//
//   node scripts/backup.mjs              → backups/inteltrace-<timestamp>.db
//   node scripts/backup.mjs --out D:/x   → write elsewhere (e.g. an external drive)
//   node scripts/backup.mjs --keep 30    → retain the newest 30 (default 14)
//
// Uses SQLite's own VACUUM INTO, which takes a consistent snapshot while the
// server is running. Copying the file with `cp` would not: a concurrent write
// leaves the copy torn, and the -wal sidecar would be missing.

import { DatabaseSync } from 'node:sqlite';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, unlinkSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i !== -1 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

function readEnvFile(file) {
  const out = {};
  if (!existsSync(file)) return out;
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    let val = trimmed.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[trimmed.slice(0, eq).trim()] = val;
  }
  return out;
}

function abs(p) {
  return isAbsolute(p) ? p : join(process.cwd(), p);
}

const fileEnv = readEnvFile('.env');
const dataDir = process.env.DATA_DIR || fileEnv.DATA_DIR || 'data';
const dbPath = join(abs(dataDir), 'inteltrace.db');

if (!existsSync(dbPath)) {
  console.error(`No database at ${dbPath} — nothing to back up.`);
  process.exit(1);
}

const outDir = abs(arg('out', 'backups'));
const keep = Math.max(1, Number(arg('keep', '14')) || 14);

mkdirSync(outDir, { recursive: true });

// 2026-09-19T14-03-21 — filename-safe, sorts chronologically as a string.
const stamp = new Date().toISOString().replace(/\.\d+Z$/, '').replace(/:/g, '-');
const target = join(outDir, `inteltrace-${stamp}.db`);

if (existsSync(target)) {
  console.error(`Refusing to overwrite an existing backup at ${target}.`);
  process.exit(1);
}

// Read-only handle: a backup must never be able to mutate the live database.
const db = new DatabaseSync(dbPath, { readOnly: true });
try {
  // Bound as a parameter, not interpolated — an --out path is caller-supplied.
  db.prepare('VACUUM INTO ?').run(target);
} finally {
  db.close();
}

const cases = (() => {
  const snap = new DatabaseSync(target, { readOnly: true });
  try {
    const row = snap.prepare("SELECT COUNT(*) AS n FROM docs WHERE collection = 'cases_v2'").get();
    return row?.n ?? 0;
  } finally {
    snap.close();
  }
})();

const sizeMb = (statSync(target).size / 1024 / 1024).toFixed(2);
console.log(`Wrote ${target} — ${cases} cases, ${sizeMb} MB.`);

// Rotate: keep the newest `keep` snapshots, drop the rest.
const existing = readdirSync(outDir)
  .filter((f) => /^inteltrace-.*\.db$/.test(f))
  .sort()
  .reverse();

for (const stale of existing.slice(keep)) {
  unlinkSync(join(outDir, stale));
  console.log(`Pruned ${stale}`);
}

if (outDir.startsWith(abs(dataDir)) || outDir === process.cwd()) {
  console.warn(
    'Note: this backup sits next to the live database. Copy it to a separate drive — ' +
      'a disk failure would take both.',
  );
}
