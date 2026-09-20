// Reset the demo investigator account.
//
// Deletes the `users/{badge}` row so the next login re-runs first-time enrolment.
// Talks to the local SQLite file directly — no server and no credentials needed.
//
//   node scripts/reset_demo.mjs [badgeId]

import { DatabaseSync } from 'node:sqlite';
import { existsSync, readFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

/** Minimal .env reader — only used to pick up DATA_DIR when the shell has not set it. */
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

const fileEnv = readEnvFile('.env');
const dataDir = process.env.DATA_DIR || fileEnv.DATA_DIR || 'data';
const dbPath = join(isAbsolute(dataDir) ? dataDir : join(process.cwd(), dataDir), 'inteltrace.db');

if (!existsSync(dbPath)) {
  console.error(`No database at ${dbPath} — nothing to reset.`);
  process.exit(1);
}

const badgeId = process.argv[2] || 'inspector@cybercrime.gov.in';
const docId = badgeId.trim().replace(/[^A-Za-z0-9._@-]/g, '_');

const db = new DatabaseSync(dbPath);
const { changes } = db.prepare('DELETE FROM docs WHERE collection = ? AND id = ?').run('users', docId);
db.close();

console.log(
  changes > 0
    ? `Deleted users/${docId} — demo account reset.`
    : `users/${docId} was not present; nothing to delete.`,
);
