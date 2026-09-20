// Case + dashboard read layer.
//
// Shared by the read endpoints (api/cases, api/cases/[id], api/dashboard) and by
// the data-driven pages (results / index / history) which call these directly
// from their server-rendered frontmatter — no internal HTTP round-trip, no cookie
// forwarding. Every function is a thin, typed read over the local SQLite store.

import { getDoc, queryCollection, deleteDoc, patchDoc } from './store';
import type { CaseDocument } from './viewmodel';

// ─────────────────────────────────────────────────────────────────────────────
// Global stats (dashboard). Single source of truth — api/analyze imports these.
// ─────────────────────────────────────────────────────────────────────────────

export interface GlobalStats {
  activeCases: number;
  reportsGenerated: number;
  anomaliesDetected: number;
  criticalAlerts: number;
  sourcesIngested: number;
  correlationsRun: number;
}

// Baseline for empty system. Persisted at stats/global.
export const STATS_BASELINE: GlobalStats = {
  activeCases: 0,
  reportsGenerated: 0,
  anomaliesDetected: 0,
  criticalAlerts: 0,
  sourcesIngested: 0,
  correlationsRun: 0,
};

/** stats/global if present and well-formed, else the baseline. */
export async function getGlobalStats(env: Env): Promise<GlobalStats> {
  try {
    const cur = (await getDoc(env, 'stats/global')) as unknown as GlobalStats | null;
    if (cur && typeof cur.reportsGenerated === 'number') {
      return {
        activeCases: num(cur.activeCases, STATS_BASELINE.activeCases),
        reportsGenerated: num(cur.reportsGenerated, STATS_BASELINE.reportsGenerated),
        anomaliesDetected: num(cur.anomaliesDetected, STATS_BASELINE.anomaliesDetected),
        criticalAlerts: num(cur.criticalAlerts, STATS_BASELINE.criticalAlerts),
        sourcesIngested: num(cur.sourcesIngested, STATS_BASELINE.sourcesIngested),
        correlationsRun: num(cur.correlationsRun, STATS_BASELINE.correlationsRun),
      };
    }
  } catch {
    /* fall through to baseline */
  }
  return { ...STATS_BASELINE };
}

function num(v: unknown, fallback: number): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback;
}

// ─────────────────────────────────────────────────────────────────────────────
// Case list rows (history + dashboard "recent cases")
// ─────────────────────────────────────────────────────────────────────────────

export interface CaseListRow {
  id: string;
  suspect: string;
  date: string;
  sources: string[];
  risk: string;
  score: number;
  status: string;
  correlations: number;
  anomalies: number;
}

function toRow(d: Record<string, unknown>): CaseListRow {
  const correlations = Array.isArray(d.correlations) ? d.correlations.length : 0;
  return {
    id: String(d.caseId ?? d._name ?? '').split('/').pop() || String(d.caseId ?? ''),
    suspect: String(d.suspect ?? (d.suspectInfo as any)?.name ?? 'Unknown'),
    date: String(d.date ?? ''),
    sources: Array.isArray(d.sources) ? (d.sources as string[]) : [],
    risk: String(d.risk ?? 'LOW'),
    score: num(d.score, 0),
    status: String(d.status ?? 'ACTIVE'),
    correlations,
    anomalies: num(d.anomaliesCount, 0),
  };
}

/** Validate case ID against path traversal or malicious characters. */
export function isValidCaseId(id: string): boolean {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id.trim());
}

/**
 * Newest first, by the decrypted `createdAt`.
 *
 * `queryCollection` already orders by the extracted `created_at` column, but a
 * document whose createdAt only exists inside the encrypted payload has NULL
 * there and sorts to the end. After decryption the real timestamp is available,
 * so this second pass puts such a case back in its rightful place. Over the 100
 * rows the queries cap at, the cost is nil.
 */
function byNewestFirst(a: Record<string, unknown>, b: Record<string, unknown>): number {
  const tA = new Date((a.createdAt as string) || 0).getTime();
  const tB = new Date((b.createdAt as string) || 0).getTime();
  return tB - tA;
}

/** All cases, most recently analysed first. */
export async function listCases(env: Env, limit = 100): Promise<CaseListRow[]> {
  const docs = await queryCollection(env, 'cases_v2', { limit });
  docs.sort(byNewestFirst);
  return docs.map(toRow);
}

/** The full denormalised view-model for one case (Results page), or null. */
export async function getCaseDoc(env: Env, id: string): Promise<CaseDocument | null> {
  const cleanId = id.trim();
  if (!isValidCaseId(cleanId)) return null;
  const doc = await getDoc(env, `cases_v2/${cleanId}`);
  return (doc as unknown as CaseDocument) ?? null;
}

/** Close/remove a case. */
export async function removeCase(env: Env, id: string): Promise<void> {
  const cleanId = id.trim();
  if (!isValidCaseId(cleanId)) throw new Error('Invalid case identifier');
  await deleteDoc(env, `cases_v2/${cleanId}`);
}

/** Change a case's status (e.g. ACTIVE → CLOSED) without touching encrypted fields. */
export async function closeCase(env: Env, id: string, status: 'CLOSED' | 'ACTIVE'): Promise<void> {
  const cleanId = id.trim();
  if (!isValidCaseId(cleanId)) throw new Error('Invalid case identifier');
  // Patch only the indexable status column. The store refuses field paths that
  // live inside the encrypted payload, so this can never clobber case evidence.
  await patchDoc(env, `cases_v2/${cleanId}`, { status }, ['status']);
}

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard payload
// ─────────────────────────────────────────────────────────────────────────────

export interface RiskBreakdownStats {
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface SourceVectorStat {
  label: string;
  sourceKey: string;
  casesCount: number;
  flags: number;
  pct: number;
  color: string;
}

export interface ActivityTelemetry {
  caseId: string;
  dateLabel: string;
  hourlyCounts: number[];
  peakHour: number;
  peakHourLabel: string;
  totalEvents: number;
}

export interface DashboardPayload {
  stats: GlobalStats;
  recent: CaseListRow[];
  /**
   * The active high-risk cases that produce `stats.criticalAlerts`. Carried
   * explicitly so the notification bell can list the exact cases it is counting:
   * `recent` is only the newest 6, so deriving the list from it would show fewer
   * items than the badge claims.
   */
  criticalCases: CaseListRow[];
  totalCases: number;
  riskBreakdown: RiskBreakdownStats;
  sourceVectors: SourceVectorStat[];
  activityTelemetry: ActivityTelemetry;
}

export async function getDashboard(env: Env): Promise<DashboardPayload> {
  const docs = await queryCollection(env, 'cases_v2', { limit: 100 });
  docs.sort(byNewestFirst);

  const cases = docs.map(toRow);
  const totalCases = cases.length;

  // Derive real active, critical, anomaly counts from actual registered cases
  const activeCasesList = cases.filter((c) => c.status === 'ACTIVE');
  const activeCases = activeCasesList.length;
  
  const getDerivedRisk = (c: any) => {
    if (c.risk === 'CRITICAL' || c.risk === 'HIGH') return 'HIGH';
    if (c.risk === 'MEDIUM') return 'MEDIUM';
    if (c.risk === 'LOW') return 'LOW';
    if (c.score >= 80) return 'HIGH';
    if (c.score >= 40) return 'MEDIUM';
    return 'LOW';
  };

  const criticalCases = activeCasesList.filter((c) => getDerivedRisk(c) === 'HIGH');
  const highRisk = criticalCases.length;
  const medRisk = activeCasesList.filter((c) => getDerivedRisk(c) === 'MEDIUM').length;
  const lowRisk = activeCasesList.filter((c) => getDerivedRisk(c) === 'LOW').length;
  const totalAnomalies = cases.reduce((acc, c) => acc + (c.anomalies || 0), 0);

  // Calculate true dynamic stats based on user's actual cases instead of mock global stats
  const liveStats: GlobalStats = {
    activeCases: activeCases,
    reportsGenerated: cases.filter((c) => c.status === 'CLOSED').length,
    anomaliesDetected: totalAnomalies,
    criticalAlerts: highRisk,
    sourcesIngested: cases.reduce((acc, c) => acc + (c.sources ? c.sources.length : 0), 0),
    correlationsRun: cases.reduce((acc, c) => acc + (c.correlations || 0), 0),
  };

  // Source vector occurrences and real flags across existing cases
  const srcOccurrences: Record<string, number> = { cdr: 0, ipdr: 0, bank: 0, social: 0, crypto: 0 };
  const srcFlags: Record<string, number> = { cdr: 0, ipdr: 0, bank: 0, social: 0, crypto: 0 };

  for (const doc of docs) {
    const cSources = Array.isArray(doc.sources) ? (doc.sources as string[]) : [];
    for (const s of cSources) {
      const k = s.toLowerCase();
      if (k.includes('cdr')) srcOccurrences.cdr++;
      else if (k.includes('ipdr')) srcOccurrences.ipdr++;
      else if (k.includes('bank')) srcOccurrences.bank++;
      else if (k.includes('social')) srcOccurrences.social++;
      else if (k.includes('crypto') || k.includes('chain')) srcOccurrences.crypto++;
    }

    if (Array.isArray(doc.cdrEvents)) {
      srcFlags.cdr += doc.cdrEvents.filter((e: any) => e?.flagged).length;
    }
    if (Array.isArray(doc.ipdrEvents)) {
      srcFlags.ipdr += doc.ipdrEvents.filter((e: any) => e?.flagged).length;
    }
    if (Array.isArray(doc.bankEvents)) {
      srcFlags.bank += doc.bankEvents.filter((e: any) => e?.flagged).length;
    }
    if (Array.isArray(doc.socialEvents)) {
      srcFlags.social += doc.socialEvents.filter((e: any) => e?.flagged).length;
    }
    if (Array.isArray(doc.cryptoEvents)) {
      srcFlags.crypto += doc.cryptoEvents.filter((e: any) => e?.flagged).length;
    }
    if (Array.isArray(doc.correlations)) {
      for (const cr of doc.correlations as any[]) {
        const p = String(cr?.pair || '').toLowerCase();
        if (p.includes('cdr')) srcFlags.cdr++;
        if (p.includes('ipdr')) srcFlags.ipdr++;
        if (p.includes('bank')) srcFlags.bank++;
        if (p.includes('social')) srcFlags.social++;
        if (p.includes('crypto') || p.includes('blockchain')) srcFlags.crypto++;
      }
    }
  }

  const maxVector = Math.max(1, totalCases);
  const sourceVectors: SourceVectorStat[] = [
    { label: 'CDR Telecom',   sourceKey: 'cdr',    casesCount: srcOccurrences.cdr,    flags: srcFlags.cdr,    pct: Math.min(100, Math.round((srcOccurrences.cdr / maxVector) * 100)),    color: '#60A5FA' },
    { label: 'IPDR Internet', sourceKey: 'ipdr',   casesCount: srcOccurrences.ipdr,   flags: srcFlags.ipdr,   pct: Math.min(100, Math.round((srcOccurrences.ipdr / maxVector) * 100)),   color: '#A78BFA' },
    { label: 'Bank Records',  sourceKey: 'bank',   casesCount: srcOccurrences.bank,   flags: srcFlags.bank,   pct: Math.min(100, Math.round((srcOccurrences.bank / maxVector) * 100)),   color: '#34D399' },
    { label: 'Social Media',  sourceKey: 'social', casesCount: srcOccurrences.social, flags: srcFlags.social, pct: Math.min(100, Math.round((srcOccurrences.social / maxVector) * 100)), color: '#F472B6' },
    { label: 'Blockchain',    sourceKey: 'crypto', casesCount: srcOccurrences.crypto, flags: srcFlags.crypto, pct: Math.min(100, Math.round((srcOccurrences.crypto / maxVector) * 100)), color: '#FFB300' },
  ];

  // 24-Hour activity telemetry computed from the most recent case
  const hourlyCounts = new Array(24).fill(0);
  let featuredCaseId = '';
  let featuredCaseDate = '';
  let totalEventsInTelemetry = 0;

  if (docs.length > 0) {
    const topDoc = docs[0];
    featuredCaseId = String(topDoc.caseId || (topDoc._name as string)?.split('/').pop() || '');
    featuredCaseDate = String(topDoc.date || (topDoc.suspectInfo as any)?.dateRange || '');

    const eventsToCount: unknown[] = [
      ...(Array.isArray(topDoc.timelineEvents) ? topDoc.timelineEvents : []),
      ...(Array.isArray(topDoc.cdrEvents) ? topDoc.cdrEvents : []),
      ...(Array.isArray(topDoc.ipdrEvents) ? topDoc.ipdrEvents : []),
      ...(Array.isArray(topDoc.bankEvents) ? topDoc.bankEvents : []),
      ...(Array.isArray(topDoc.socialEvents) ? topDoc.socialEvents : []),
    ];

    for (const ev of eventsToCount) {
      const rawTime = (ev as any)?.timestamp || (ev as any)?.time;
      if (typeof rawTime === 'string') {
        const mIso = /[T ](\d{2}):/.exec(rawTime);
        if (mIso) {
          const h = parseInt(mIso[1], 10);
          if (h >= 0 && h < 24) {
            hourlyCounts[h]++;
            totalEventsInTelemetry++;
          }
        } else {
          const mTime = /(\d{1,2}):(\d{2})(?:\s*([AP]M))?/i.exec(rawTime);
          if (mTime) {
            let h = parseInt(mTime[1], 10);
            const ampm = (mTime[3] || '').toUpperCase();
            if (ampm === 'PM' && h < 12) h += 12;
            if (ampm === 'AM' && h === 12) h = 0;
            if (h >= 0 && h < 24) {
              hourlyCounts[h]++;
              totalEventsInTelemetry++;
            }
          }
        }
      }
    }
  }

  let maxCount = 0;
  let peakHour = -1;
  for (let h = 0; h < 24; h++) {
    if (hourlyCounts[h] > maxCount) {
      maxCount = hourlyCounts[h];
      peakHour = h;
    }
  }
  const peakHourLabel =
    peakHour === -1
      ? 'None'
      : peakHour === 0
        ? '12 AM'
        : peakHour < 12
          ? `${peakHour} AM`
          : peakHour === 12
            ? '12 PM'
            : `${peakHour - 12} PM`;

  return {
    stats: liveStats,
    recent: cases.slice(0, 6),
    criticalCases,
    totalCases,
    riskBreakdown: {
      high: highRisk,
      medium: medRisk,
      low: lowRisk,
      total: totalCases,
    },
    sourceVectors,
    activityTelemetry: {
      caseId: featuredCaseId,
      dateLabel: featuredCaseDate,
      hourlyCounts,
      peakHour,
      peakHourLabel,
      totalEvents: totalEventsInTelemetry,
    },
  };
}
