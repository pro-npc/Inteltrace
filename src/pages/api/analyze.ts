import type { APIRoute } from 'astro';
import { fail, getEnv, clientIp } from '../../lib/http';
import { requireSession } from '../../lib/auth';
import { setDoc, getDoc } from '../../lib/store';
import { audit } from '../../lib/audit';
import { parseAllSources, type ParsedSources } from '../../lib/csv';
import { resolveCrypto } from '../../lib/crypto-apis';
import { correlateAll } from '../../lib/correlate';
import { detectAnomalies } from '../../lib/anomaly';
import { computeRisk, deriveRiskSignals } from '../../lib/risk';
import {
  buildDynamicCaseDocument,
  type EvidenceHash,
  type CaseDocument,
} from '../../lib/viewmodel';
import { STATS_BASELINE, type GlobalStats } from '../../lib/cases';

export const prerender = false;

// ── multipart ingestion pipeline ─────────────────────────────────────────────
// Multipart form: 4 CSV files (cdr/ipdr/bank/social) + wallet + suspect fields →
// real SHA-256 per file → parse → (golden signature? authored narrative :
// dynamic engine) → persist cases/{id}, bump stats/global → { caseId }.

/** SHA-256 (hex) of a file's bytes — the real §65B evidence hash. */
async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', buf);
  const bytes = new Uint8Array(digest);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
  return hex;
}

const MAX_FILE_SIZE = 8 * 1024 * 1024; // 8MB per file — four concurrent uploads stay well inside the Node heap

/** Read a form file → { text, hash entry }. Returns null when the field is absent. */
async function readFile(
  form: FormData,
  field: string,
  source: string,
): Promise<{ text: string; hash: EvidenceHash } | null> {
  const f = form.get(field);
  if (!(f instanceof File) || f.size === 0) return null;
  if (f.size > MAX_FILE_SIZE) throw new Error(`${source} file exceeds the 8MB limit (size: ${(f.size / 1024 / 1024).toFixed(1)}MB).`);
  
  const buf = await f.arrayBuffer();
  return {
    text: new TextDecoder().decode(buf),
    hash: {
      filename: f.name || `${field}.csv`,
      sha256: await sha256Hex(buf),
      sizeBytes: f.size,
      source,
    },
  };
}

/** We no longer reconcile a single credit; resolveCrypto takes the whole bank array. */
function reconcileCredit(parsed: ParsedSources): any[] {
  return parsed.bank;
}

function newCaseId(): string {
  const year = new Date().getFullYear();
  const suffix = String(Date.now() % 100000).padStart(5, '0');
  return `CASE-${year}-${suffix}`;
}

async function bumpStats(env: Env, doc: CaseDocument, isNewCase: boolean): Promise<void> {
  try {
    const cur = (await getDoc(env, 'stats/global')) as unknown as GlobalStats | null;
    const base: GlobalStats = cur && typeof cur.reportsGenerated === 'number' ? cur : { ...STATS_BASELINE };
    const rows =
      doc.sourceCounts.cdr +
      doc.sourceCounts.ipdr +
      doc.sourceCounts.bank +
      doc.sourceCounts.social +
      doc.sourceCounts.crypto;
    const next: GlobalStats = {
      activeCases: base.activeCases + (isNewCase ? 1 : 0),
      reportsGenerated: base.reportsGenerated,
      anomaliesDetected: base.anomaliesDetected + doc.anomaliesCount,
      criticalAlerts: base.criticalAlerts + (doc.suspectInfo.riskLevel === 'CRITICAL' ? 1 : 0),
      sourcesIngested: base.sourcesIngested + rows,
      correlationsRun: base.correlationsRun + doc.correlations.length,
    };
    await setDoc(env, 'stats/global', next as unknown as Record<string, unknown>);
  } catch {
    /* stats are best-effort; never fail an analysis on a stats write */
  }
}

// ── In-memory IP rate limiter (6 uploads per 10 minutes per IP) ──────────────
const uploadLimits = new Map<string, { count: number; expires: number }>();

function checkUploadLimit(ip: string): boolean {
  const now = Date.now();
  const rec = uploadLimits.get(ip);
  if (!rec || rec.expires <= now) {
    if (rec) uploadLimits.delete(ip);
    uploadLimits.set(ip, { count: 1, expires: now + 10 * 60_000 });
    return true;
  }
  rec.count++;
  return rec.count <= 6;
}

// ── CSRF origin validation ───────────────────────────────────────────────────
// The server binds to the investigator's own machine, so the only legitimate
// origins are loopback and whatever host the request itself arrived on (covers a
// LAN address when `--host` is used). Nothing external is allowed.
function validateOrigin(request: Request, _env: Env): boolean {
  const origin = request.headers.get('origin') || '';
  const referer = request.headers.get('referer') || '';
  if (!origin && !referer) return true;

  let reqOrigin = '';
  try { reqOrigin = new URL(request.url).origin; } catch {}

  const allowed = [
    'http://localhost',
    'https://localhost',
    'http://127.0.0.1',
    'https://127.0.0.1',
  ];
  if (reqOrigin) allowed.push(reqOrigin);

  return allowed.some(a => origin.startsWith(a) || referer.startsWith(a));
}

export const POST: APIRoute = async (context) => {
  const env = getEnv(context.locals);

  // CSRF check
  if (!validateOrigin(context.request, env)) {
    return fail('Forbidden — cross-origin requests are not allowed', 403);
  }

  const guard = await requireSession(context.request, env);
  if (!guard) {
    return fail('Unauthorized', 401);
  }
  // Rate limit uploads per IP
  const ip = clientIp(context.request);
  if (!checkUploadLimit(ip)) {
    return fail('Too many uploads. Please wait before submitting again.', 429);
  }

  let form: FormData;
  try {
    form = await context.request.formData();
  } catch {
    return fail('Expected multipart/form-data with CSV files', 400);
  }

  let cdrF, ipdrF, bankF, socialF;
  try {
    [cdrF, ipdrF, bankF, socialF] = await Promise.all([
      readFile(form, 'cdr', 'CDR'),
      readFile(form, 'ipdr', 'IPDR'),
      readFile(form, 'bank', 'Bank'),
      readFile(form, 'social', 'Social'),
    ]);
  } catch (err: any) {
    return fail(err.message || 'Payload Too Large', 413);
  }

  if (!cdrF && !ipdrF && !bankF && !socialF) {
    return fail('Upload at least one evidence file (cdr / ipdr / bank / social)', 400);
  }

  try {
    const parsed = parseAllSources({
      cdr: cdrF?.text ?? '',
      ipdr: ipdrF?.text ?? '',
      bank: bankF?.text ?? '',
      social: socialF?.text ?? '',
    });

    const evidenceHashes: EvidenceHash[] = [cdrF, ipdrF, bankF, socialF]
      .filter((f): f is { text: string; hash: EvidenceHash } => f !== null)
      .map((f) => f.hash);

function cleanInput(val: unknown, maxLen = 60): string {
  if (typeof val !== 'string') return '';
  return val.replace(/<[^>]*>/g, '').replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, maxLen);
}

function cleanPhone(val: unknown): string {
  const s = cleanInput(val, 25);
  return /^[+0-9\s\-()xX.]{0,25}$/.test(s) ? s : '';
}

function cleanWallet(val: unknown): string {
  const s = cleanInput(val, 66);
  return /^[0-9a-zA-Z]{0,66}$/.test(s) ? s : '';
}

    const wallet = cleanWallet(form.get('wallet'));
    const rawExchange = cleanInput(form.get('exchange'), 30);
    const exchange = rawExchange || 'WazirX';
    const createdAt = new Date().toISOString();

    const suspectData = {
      name: cleanInput(form.get('suspectName'), 60) || undefined,
      alias: cleanInput(form.get('alias'), 40) || undefined,
      fir: cleanInput(form.get('fir'), 40) || undefined,
      officer: cleanInput(form.get('officer'), 60) || undefined,
      phone: cleanPhone(form.get('phone')) || undefined,
      bankAccount: cleanInput(form.get('bankAccount'), 34) || undefined,
    };

    let doc: CaseDocument;
    
    // Always use the dynamic path to ensure custom uploaded files are never 
    // inadvertently matched to the demo case due to mixed sample data.
    const crypto = await resolveCrypto(wallet, reconcileCredit(parsed), exchange, env.ETHERSCAN_API_KEY);
    const correlations = correlateAll(parsed, crypto);
    const anomalies = detectAnomalies(parsed, crypto, wallet);
    const risk = computeRisk(correlations, anomalies, deriveRiskSignals(parsed));
    
    // OmniRoute AI Intelligence Enrichement
    let aiEnrichedData = null;
    if (env.OMNIROUTE_API_KEY) {
      try {
        const { runAIForensicAnalysis } = await import('../../lib/omni-intelligence');
        aiEnrichedData = await runAIForensicAnalysis(
          parsed,
          env.OMNIROUTE_API_KEY,
          env.OMNIROUTE_BASE_URL || 'http://localhost:20128/v1',
          env.OMNIROUTE_PRIMARY_MODEL || 'antigravity/gemini-3.7-flash-high',
          env.OMNIROUTE_VALIDATOR_MODEL || 'antigravity/gemini-3.7-flash-low'
        );
      } catch (e) {
        console.error('Failed to run AI Enrichment:', e);
      }
    }

    doc = buildDynamicCaseDocument({
      caseId: newCaseId(),
      createdAt,
      wallet,
      suspect: suspectData,
      parsed,
      crypto,
      correlations,
      anomalies,
      risk,
      evidenceHashes,
      aiEnrichedData
    });

    // Is this a brand-new case id (for the activeCases / reports counters)?
    const existing = await getDoc(env, `cases_v2/${doc.caseId}`).catch(e => { console.error('getDoc fail', e); return null; });
    const isNewCase = !existing;

    await setDoc(env, `cases_v2/${doc.caseId}`, doc as unknown as Record<string, unknown>).catch(e => console.error('setDoc fail', e));
    await bumpStats(env, doc, isNewCase).catch(e => console.error('bumpStats fail', e));

    await audit(env, {
      badgeId: guard.session.sub,
      ip: clientIp(context.request),
      ua: context.request.headers.get('user-agent') || '',
      event: `analyze:${doc.caseId}`,
    }).catch(e => console.error('audit fail', e));

    const headers = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    headers.append('set-cookie', guard.setCookie);
    return new Response(JSON.stringify({ caseId: doc.caseId, score: doc.score, risk: doc.risk }), {
      status: 200,
      headers,
    });
  } catch (err: any) {
    console.error('Analyze API Error:', err);
    return fail(`Analysis Error: ${err.message || 'Internal processing failed'}`, 500);
  }
};
