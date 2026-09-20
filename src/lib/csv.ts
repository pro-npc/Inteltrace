// Dependency-free CSV parsing + per-source column mappers.
//
// The Worker runtime (V8) has no Node stream/fs and we deliberately avoid a
// papaparse dependency to keep the bundle tiny. This parser handles RFC-4180
// essentials: quoted fields, embedded commas/newlines, escaped double-quotes,
// and CRLF/LF line endings. Column contracts follow prototype.md exactly.

export interface CdrRow {
  id: string;
  timestamp: string; // ISO, joined from date + time
  type: string; // 'call' | 'sms'
  imei: string;
  from: string;
  to: string;
  duration: number; // seconds
  tower: string;
  towerLat: number | null;
  towerLong: number | null;
}

export interface IpdrRow {
  id: string;
  timestamp: string; // session_start (ISO)
  sessionEnd: string;
  device: string;
  imei: string;
  ip: string;
  domain: string;
  dataMB: number;
  locationLat: number | null;
  locationLong: number | null;
}

export interface BankRow {
  id: string;
  timestamp: string; // ISO, joined from date + time
  txnType: string; // NEFT | IMPS | RTGS ...
  type: 'CREDIT' | 'DEBIT';
  amount: number;
  currency: string;
  account: string;
  sender: string;
  receiver: string;
  senderAcc: string;
  receiverAcc: string;
  description: string;
  bankName: string;
}

export interface SocialRow {
  id: string;
  timestamp: string; // post_timestamp (ISO)
  platform: string;
  username: string;
  loginIp: string;
  device: string;
  locationTag: string | null;
  locationLat: number | null;
  locationLng: number | null;
  caption: string;
  taggedAccounts: string | null;
}

export interface ParsedSources {
  cdr: CdrRow[];
  ipdr: IpdrRow[];
  bank: BankRow[];
  social: SocialRow[];
}

/**
 * High performance CSV parser that yields mapped objects directly without
 * allocating intermediate string[][] or Record<string, string>[] arrays.
 * It also caches RegExp-to-column-index lookups to avoid O(N*M) regex tests.
 */
function parseAndMapCsv<T>(
  text: string,
  rowMapper: (cells: string[], get: (patterns: RegExp[]) => string, rowIndex: number) => T | null
): T[] {
  if (!text) return [];
  const s = text.replace(/^﻿/, ''); // strip BOM

  // FAST PATH: If no quotes, use native String.split (10x-50x faster, saves Cloudflare 50ms CPU limit)
  if (s.indexOf('"') === -1) {
    const lines = s.split(/\r?\n/);
    if (lines.length < 2) return [];
    const header = lines[0].split(',').map(h => h.trim().toLowerCase());
    const headerCache = new Map<RegExp, number>();
    
    const out: T[] = [];
    for (let rowIndex = 1; rowIndex < lines.length; rowIndex++) {
      const line = lines[rowIndex].trim();
      if (!line) continue;
      const cells = line.split(',');
      
      const getField = (patterns: RegExp[]): string => {
        for (const p of patterns) {
          if (headerCache.has(p)) {
            const idx = headerCache.get(p)!;
            return idx === -1 ? '' : (cells[idx] ?? '').trim();
          }
          for (let i = 0; i < header.length; i++) {
            if (p.test(header[i])) {
              headerCache.set(p, i);
              return (cells[i] ?? '').trim();
            }
          }
          headerCache.set(p, -1);
        }
        return '';
      };
      
      const item = rowMapper(cells, getField, rowIndex - 1);
      if (item) out.push(item);
    }
    return out;
  }

  // SLOW PATH: RFC-4180 character-by-character state machine for handling quoted fields
  let field = '';
  let row: string[] = [];
  let inQuotes = false;
  
  const out: T[] = [];
  let rowIndex = 0;
  
  let header: string[] = [];
  let headerCache: Map<RegExp, number> | null = null;
  
  const getField = (patterns: RegExp[], cells: string[]): string => {
    if (!headerCache) return '';
    for (const p of patterns) {
      if (headerCache.has(p)) {
        const idx = headerCache.get(p)!;
        return (cells[idx] ?? '').trim();
      }
      for (let i = 0; i < header.length; i++) {
        if (p.test(header[i])) {
          headerCache.set(p, i);
          return (cells[i] ?? '').trim();
        }
      }
    }
    return '';
  };

  const processRow = () => {
    if (row.length === 0 && field === '') return;
    row.push(field);
    
    if (rowIndex === 0) {
      header = row.map(h => h.trim());
      headerCache = new Map();
    } else {
      if (row.length === 1 && row[0].trim() === '') {
        // skip fully empty line
      } else {
        const item = rowMapper(row, (patterns) => getField(patterns, row), rowIndex);
        if (item) out.push(item);
      }
    }
    
    row = [];
    field = '';
    rowIndex++;
  };

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inQuotes) {
      if (ch === '"') {
        if (s[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
      continue;
    }
    if (ch === '"') {
      inQuotes = true;
    } else if (ch === ',') {
      row.push(field);
      field = '';
    } else if (ch === '\n') {
      processRow();
    } else if (ch === '\r') {
      // swallow
    } else {
      field += ch;
    }
  }
  
  if (field !== '' || row.length > 0) {
    processRow();
  }
  
  return out;
}

/** Normalize a date fragment to `YYYY-MM-DD`. Accepts ISO, slash, and day-first. */
function normDate(raw: string): string {
  const s = (raw || '').trim();
  if (!s) return '';
  let m = /^(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})$/.exec(s); // YYYY-MM-DD / YYYY/MM/DD
  if (m) return `${m[1]}-${m[2].padStart(2, '0')}-${m[3].padStart(2, '0')}`;
  m = /^(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})$/.exec(s); // DD-MM-YYYY (India day-first)
  if (m) return `${m[3]}-${m[2].padStart(2, '0')}-${m[1].padStart(2, '0')}`;
  return s;
}

/** Normalize a time fragment to zero-padded `HH:MM:SS`. */
function normTime(raw: string): string {
  const s = (raw || '').trim();
  const m = /^(\d{1,2}):(\d{2})(?::(\d{2}))?/.exec(s);
  if (!m) return s;
  return `${m[1].padStart(2, '0')}:${m[2]}:${m[3] || '00'}`;
}

/**
 * Canonicalize any timestamp column to strict ISO `YYYY-MM-DDTHH:MM:SS` (local,
 * no zone). Handles combined columns ("2025-10-10 14:18"), ISO-with-T, slash and
 * day-first dates. Critical: every downstream consumer keys off the `T` separator
 * (`/T(\d{2}):/` for the hour), so a space-separated value silently defeats
 * off-hours/night-window detection and collapses time-gap math to "0 min".
 */
export function normalizeTimestamp(raw: string): string {
  const s = (raw || '').trim();
  if (!s) return '';
  const m = /^(\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{4})(?:[ T]+(\d{1,2}:\d{2}(?::\d{2})?))?/.exec(s);
  if (!m) return s;
  const d = normDate(m[1]);
  return m[2] ? `${d}T${normTime(m[2])}` : d;
}

/** Join a date + time column into a canonical ISO local timestamp. */
function joinDateTime(date: string, time: string): string {
  const d = (date || '').trim();
  const t = (time || '').trim();
  // Combined single column (date already carries the time): normalize whole.
  if (d && !t) return normalizeTimestamp(d);
  if (!d) return normalizeTimestamp(t);
  if (!t) return normDate(d);
  return `${normDate(d)}T${normTime(t)}`;
}

type Getter = (patterns: RegExp[]) => string;

/**
 * Time-only column patterns. Deliberately anchored so they can NEVER match a
 * combined `timestamp` header: `/^time$/` excludes it, and `/_time$/` cannot
 * match a header ending in "stamp". A loose `/time/i` here was the source of a
 * silent catastrophic bug — for a CSV with one `timestamp` column it matched the
 * same column as the date, producing `"2025-10-10 14:18T2025-10-10 14:18"`,
 * which `Date.parse` returns NaN for. Every downstream time gap then collapsed
 * to "0 min" and every off-hours check silently failed.
 */
const TIME_ONLY_PATTERNS: RegExp[] = [
  /^time$/i,
  /^(?:call|txn|transaction|event|log|post|session|start|end)_?time$/i,
  /_time$/i,
  /^time_of_day$/i,
];

/** Combined date+time column patterns, checked before any split date/time pair. */
const COMBINED_PATTERNS: RegExp[] = [
  /^(?:datetime|date_?time|timestamp|time_?stamp)$/i,
  /^(?:session_start|post_timestamp|txn_timestamp|event_timestamp)$/i,
  /timestamp/i,
];

/**
 * Resolve a canonical ISO `YYYY-MM-DDTHH:MM:SS` from whatever shape the CSV uses:
 * a single combined column, a separate date + time pair, or a date-only column.
 * `extraCombined` lets a source prepend its own preferred column (e.g. IPDR's
 * `session_start`) ahead of the generic candidates.
 */
function pickTimestamp(get: Getter, extraCombined: RegExp[] = []): string {
  const timeOnly = get(TIME_ONLY_PATTERNS);

  // 1) An explicit combined column wins when it actually carries a time.
  const combined = get([...extraCombined, ...COMBINED_PATTERNS]);
  if (combined) {
    const norm = normalizeTimestamp(combined);
    if (norm.includes('T')) return norm;
    // Date-only value sitting in a "timestamp"-named column: pair it with the
    // separate time column when one exists.
    if (timeOnly) return `${normDate(combined)}T${normTime(timeOnly)}`;
    return norm;
  }

  // 2) Fall back to a discrete date column (+ the time column when present).
  const date = get([/^date$/i, /_date$/i, /^(?:call|txn|transaction|event|log|post)_?date$/i, /date/i]);
  if (date) return joinDateTime(date, timeOnly);

  // 3) Time-only data (no date at all) — normalize what we have.
  return timeOnly ? normalizeTimestamp(timeOnly) : '';
}

function num(v: string | undefined): number {
  const n = Number((v ?? '').replace(/[, ]/g, ''));
  return Number.isFinite(n) ? n : 0;
}

function coord(v: string | undefined): number | null {
  const t = (v ?? '').trim();
  if (t === '' || t === '0') return null;
  const n = Number(t);
  return Number.isFinite(n) ? n : null;
}

/** Parse + normalize the four sources in one call. */
export function parseAllSources(files: {
  cdr: string;
  ipdr: string;
  bank: string;
  social: string;
}): ParsedSources {
  return {
    cdr: parseAndMapCsv(files.cdr, (cells, get, i) => {
      const cType = get([/call_type/i, /type/i]);
      return {
        id: `cdr-${String(i).padStart(2, '0')}`,
        timestamp: pickTimestamp(get),
        type: (cType || 'call').toLowerCase(),
        imei: get([/imei/i]),
        from: get([/caller/i, /from/i, /source/i]),
        to: get([/receiver/i, /to/i, /dest/i]),
        duration: num(get([/duration/i, /sec/i])),
        tower: get([/tower_id/i, /tower/i, /cell/i]),
        towerLat: coord(get([/tower_lat/i, /lat/i])),
        towerLong: coord(get([/tower_long/i, /long/i, /lng/i])),
      };
    }),
    
    ipdr: parseAndMapCsv(files.ipdr, (cells, get, i) => {
      const end = get([/session_end/i, /end_time/i, /^end$/i, /end/i]);
      return {
        id: `ipdr-${String(i).padStart(2, '0')}`,
        timestamp: pickTimestamp(get, [/session_start/i, /^start$/i, /start_time/i]),
        sessionEnd: normalizeTimestamp(end),
        device: get([/device/i, /model/i]),
        imei: get([/imei/i]),
        ip: get([/ip_address/i, /ip/i]),
        domain: get([/domain/i, /url/i, /site/i]),
        dataMB: num(get([/data_mb/i, /data/i, /volume/i])),
        locationLat: coord(get([/location_lat/i, /lat/i])),
        locationLong: coord(get([/location_long/i, /long/i, /lng/i])),
      };
    }),
    
    bank: parseAndMapCsv(files.bank, (cells, get, i) => {
      const crdr = get([/cr_dr/i, /credit_debit/i, /dr_cr/i, /type/i]).toUpperCase();
      const type: 'CREDIT' | 'DEBIT' = (crdr === 'CR' || crdr === 'CREDIT') ? 'CREDIT' : 'DEBIT';
      return {
        id: `bank-${String(i).padStart(2, '0')}`,
        timestamp: pickTimestamp(get),
        txnType: get([/transaction_type/i, /txn/i, /mode/i]),
        type,
        amount: num(get([/amount/i, /value/i])),
        currency: get([/currency/i]) || 'INR',
        account: get([/account_number/i, /^account$/i, /acc_num/i]),
        sender: get([/sender_name/i, /sender/i, /remitter/i]),
        receiver: get([/receiver_name/i, /receiver/i, /beneficiary/i]),
        senderAcc: get([/sender_account/i, /remitter_acc/i]),
        receiverAcc: get([/receiver_account/i, /beneficiary_acc/i]),
        description: get([/description/i, /remarks/i, /particulars/i]),
        bankName: get([/bank_name/i, /bank/i]),
      };
    }),
    
    social: parseAndMapCsv(files.social, (cells, get, i) => {
      const tag = get([/location_tag/i, /geotag/i, /location(?!_(?:lat|long|lng))/i]);
      const tagged = get([/tagged/i]);
      return {
        id: `soc-${String(i).padStart(2, '0')}`,
        timestamp: pickTimestamp(get, [/post_timestamp/i, /post_time/i]),
        locationLat: coord(get([/location_lat/i, /^lat/i])),
        locationLng: coord(get([/location_long/i, /location_lng/i, /^lng/i, /^long/i])),
        platform: get([/platform/i, /app/i]),
        username: get([/username/i, /handle/i, /account/i]),
        loginIp: get([/login_ip/i, /ip/i]),
        device: get([/device/i, /model/i]),
        locationTag: tag === '' ? null : tag,
        caption: get([/caption/i, /text/i, /content/i]),
        taggedAccounts: tagged === '' ? null : tagged,
      };
    })
  };
}
