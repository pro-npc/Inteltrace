import { addDoc } from './store';

export interface AuditEntry {
  badgeId: string;
  ip: string;
  ua: string;
  event: string;
}

/** Append an auth audit row. Never throws — audit failure must not block auth. */
export async function audit(env: Env, entry: AuditEntry): Promise<void> {
  try {
    await addDoc(env, 'audit', { ...entry, ts: new Date().toISOString() });
  } catch {
    /* swallow */
  }
}
