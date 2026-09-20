// Case view-model assembler.
//
// Produces the denormalised case document persisted to Firestore and read whole
// by the Results page. Field names match src/data/mockInvestigation.ts exactly so
// the frontend consumes it unchanged.
//
// Two paths:
//   • Golden — the curated dataset (matchesGoldenCase) reproduces CASE-2024-0892
//     exactly: authored arrays + real SHA-256 evidence + a risk score recomputed
//     to 87/CRITICAL from the canonical correlations.
//   • Dynamic — arbitrary uploads: everything is derived from the parsed sources,
//     the correlation engine, anomaly detection, and the risk model.

import type { ParsedSources, BankRow } from './csv';
import type { CryptoResolution, CryptoEvent } from './crypto-apis';
import type { Correlation } from './correlate';
import type { AnomalyResult, Anomaly } from './anomaly';
import { computeRisk, type RiskResult } from './risk';
import type { AIEnrichedData } from './omni-intelligence';
import {
  suspectInfo as canonicalSuspect,
  cdrEvents as canonicalCdr,
  ipdrEvents as canonicalIpdr,
  bankEvents as canonicalBank,
  socialEvents as canonicalSocial,
  cryptoEvents as canonicalCrypto,
  timelineEvents as canonicalTimeline,
  correlations as canonicalCorrelations,
  networkNodes as canonicalNodes,
  networkEdges as canonicalEdges,
  findings as canonicalFindings,
  actions as canonicalActions,
  anomalies as canonicalAnomalies,
  CANONICAL_CASE_ID,
  CANONICAL_ANOMALY_COUNT,
} from './fixtures/canonicalCase';

export interface EvidenceHash {
  filename: string;
  sha256: string;
  sizeBytes: number;
  source: string; // CDR | IPDR | Bank | Social
}

export interface SourceCounts {
  cdr: number;
  ipdr: number;
  bank: number;
  social: number;
  crypto: number;
}

/** One entity in the link-analysis graph. `x`/`y` are pre-laid-out canvas coordinates. */
export interface NetworkNode {
  id: string;
  label: string;
  sublabel: string;
  color: string;
  size: number;
  x: number;
  y: number;
  /** Optional AI-supplied context bullets shown in the node inspector. */
  facts?: string[];
}

/** One relationship in the link-analysis graph. `dashed` marks an inferred link. */
export interface NetworkEdge {
  from: string;
  to: string;
  label: string;
  dashed: boolean;
  /**
   * 'correlation' edges are drawn by the engine's cross-source findings rather than by
   * a single record, so the renderer highlights them — they are the conclusions an
   * investigator is looking for, not raw call/transfer plumbing.
   */
  kind?: 'structural' | 'correlation';
  /** Correlation edges only: full finding title and confidence, surfaced on hover. */
  title?: string;
  confidence?: number;
  risk?: string;
}

export interface CaseDocument {
  caseId: string;
  createdAt: string;
  suspectInfo: Record<string, unknown>;
  cdrEvents: unknown[];
  ipdrEvents: unknown[];
  bankEvents: unknown[];
  socialEvents: unknown[];
  cryptoEvents: unknown[];
  timelineEvents: unknown[];
  correlations: unknown[];
  networkNodes: NetworkNode[];
  networkEdges: NetworkEdge[];
  findings: unknown[];
  actions: string[];
  evidenceHashes: EvidenceHash[];
  sourceCounts: SourceCounts;
  anomaliesCount: number;
  /**
   * The anomalies behind `anomaliesCount`. Persisted so the Results page can show
   * what was flagged rather than only how many — a count with no list is
   * unciteable in a report and unverifiable by the investigating officer.
   */
  anomalyList: Anomaly[];
  riskBreakdown: { label: string; points: number }[];
  // Denormalised fields for the history/dashboard list rows:
  suspect: string;
  date: string;
  sources: string[];
  risk: 'HIGH' | 'MEDIUM' | 'LOW';
  score: number;
  status: string;
  aiEnriched?: boolean;
}

export interface DynamicInput {
  caseId: string;
  createdAt: string;
  wallet: string;
  suspect: {
    name?: string;
    alias?: string;
    fir?: string;
    officer?: string;
    phone?: string;
    bankAccount?: string;
  };
  parsed: ParsedSources;
  crypto: CryptoResolution;
  correlations: Correlation[];
  anomalies: AnomalyResult;
  risk: RiskResult;
  evidenceHashes: EvidenceHash[];
  aiEnrichedData?: AIEnrichedData | null;
}

function counts(parsed: ParsedSources, crypto: CryptoResolution): SourceCounts {
  return {
    cdr: parsed.cdr.length,
    ipdr: parsed.ipdr.length,
    bank: parsed.bank.length,
    social: parsed.social.length,
    crypto: crypto.events.length,
  };
}

function activeSources(c: SourceCounts): string[] {
  const s: string[] = [];
  if (c.cdr) s.push('CDR');
  if (c.ipdr) s.push('IPDR');
  if (c.bank) s.push('Bank');
  if (c.social) s.push('Social');
  if (c.crypto) s.push('Crypto');
  return s;
}

// ─────────────────────────────────────────────────────────────────────────────
// Golden path
// ─────────────────────────────────────────────────────────────────────────────

export function buildGoldenCaseDocument(
  createdAt: string,
  evidenceHashes: EvidenceHash[],
  parsed: ParsedSources,
  customSuspect?: {
    name?: string;
    fir?: string;
    officer?: string;
    phone?: string;
    bankAccount?: string;
  },
): CaseDocument {
  // Recompute risk from the authored correlations + the curated situational
  // flags — the alibi contradiction (CDR↔Social) drives the location-impossible
  // weight, the Goa/TOR night activity drives the unusual-hour weight → 87.
  const risk = computeRisk(canonicalCorrelations as unknown as Correlation[], {
    anomalies: canonicalAnomalies,
    count: CANONICAL_ANOMALY_COUNT,
    unusualHour: true,
    impossibleTravel: false,
    ofacHit: false,
  });

  const suspectName = customSuspect?.name || canonicalSuspect.name;
  const suspect = {
    ...canonicalSuspect,
    name: suspectName,
    fir: customSuspect?.fir || canonicalSuspect.fir,
    officer: customSuspect?.officer || canonicalSuspect.officer,
    phone: customSuspect?.phone || canonicalSuspect.phone,
    bankAccount: customSuspect?.bankAccount || canonicalSuspect.bankAccount,
    riskScore: risk.score,
    riskLevel: risk.level,
  };
  const sourceCounts = counts(parsed, { events: canonicalCrypto as unknown as CryptoEvent[] } as CryptoResolution);

  return {
    caseId: CANONICAL_CASE_ID,
    createdAt,
    suspectInfo: suspect,
    cdrEvents: canonicalCdr,
    ipdrEvents: canonicalIpdr,
    bankEvents: canonicalBank,
    socialEvents: canonicalSocial,
    cryptoEvents: canonicalCrypto,
    timelineEvents: canonicalTimeline,
    correlations: canonicalCorrelations,
    networkNodes: canonicalNodes,
    networkEdges: canonicalEdges,
    findings: canonicalFindings,
    actions: canonicalActions,
    evidenceHashes,
    sourceCounts,
    anomaliesCount: CANONICAL_ANOMALY_COUNT,
    anomalyList: canonicalAnomalies,
    riskBreakdown: risk.breakdown,
    suspect: suspectName,
    date: '2024-03-15',
    sources: ['CDR', 'IPDR', 'Bank', 'Social', 'Crypto'],
    risk: risk.listBadge,
    score: risk.score,
    status: 'ACTIVE',
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Dynamic path
// ─────────────────────────────────────────────────────────────────────────────

const ms = (iso: string): number => {
  const t = Date.parse(iso || '');
  return Number.isNaN(t) ? 0 : t;
};
const hourOf = (iso: string): number => {
  const m = /T(\d{2}):/.exec(iso || '');
  return m ? Number(m[1]) : -1;
};
const isOffHours = (iso: string): boolean => {
  const h = hourOf(iso);
  return h >= 22 || (h >= 0 && h < 5);
};
const fmtTime = (iso: string): string => (iso || '').slice(0, 16).replace('T', ' ');

function dateRange(parsed: ParsedSources): { range: string; latest: string } {
  const all = [
    ...parsed.cdr.map((e) => e.timestamp),
    ...parsed.ipdr.map((e) => e.timestamp),
    ...parsed.bank.map((e) => e.timestamp),
    ...parsed.social.map((e) => e.timestamp),
  ]
    .map((t) => ms(t))
    .filter((t) => t > 0)
    .sort((a, b) => a - b);
  if (all.length === 0) return { range: 'unknown', latest: new Date().toISOString().slice(0, 10) };
  const lo = new Date(all[0]).toISOString().slice(0, 10);
  const hi = new Date(all[all.length - 1]).toISOString().slice(0, 10);
  return { range: `${lo} to ${hi}`, latest: hi };
}

function mostFrequent(values: string[]): string {
  const freq = new Map<string, number>();
  for (const v of values) {
    if (!v) continue;
    freq.set(v, (freq.get(v) || 0) + 1);
  }
  let best = '';
  let max = 0;
  for (const [k, n] of freq) if (n > max) ((max = n), (best = k));
  return best;
}

function buildDynamicEvents(parsed: ParsedSources) {
  const cdrEvents = parsed.cdr.map((c) => ({
    id: c.id,
    timestamp: c.timestamp,
    type: c.type,
    from: c.from,
    to: c.to,
    duration: c.duration,
    tower: c.tower,
    location: c.tower,
    lat: c.towerLat,
    lng: c.towerLong,
    flagged: isOffHours(c.timestamp),
    flag: isOffHours(c.timestamp) ? 'Unusual-hour activity (22:00–05:00)' : undefined,
  }));

  const ipdrEvents = parsed.ipdr.map((s) => {
    const risky = /tor|vpn|proxy|\.onion/i.test(s.domain) || s.dataMB > 500;
    return {
      id: s.id,
      timestamp: s.timestamp,
      sessionEnd: s.sessionEnd,
      device: s.device,
      imei: s.imei,
      ip: s.ip,
      domain: s.domain,
      dataMB: s.dataMB,
      location: s.locationLat != null ? `${s.locationLat}, ${s.locationLong}` : 'Unknown',
      flagged: risky || isOffHours(s.timestamp),
      flag: risky ? 'TOR/VPN anonymization indicator' : isOffHours(s.timestamp) ? 'Off-hours session' : undefined,
    };
  });

  const bankEvents = parsed.bank.map((b) => {
    const big = b.amount >= 100000;
    return {
      id: b.id,
      timestamp: b.timestamp,
      type: b.type,
      amount: b.amount,
      currency: b.currency,
      description: b.description,
      sender: b.sender,
      senderAcc: b.senderAcc,
      receiverAcc: b.receiverAcc,
      flagged: big,
      flag: big ? `Large ${b.type.toLowerCase()} of ₹${b.amount.toLocaleString('en-IN')}` : undefined,
    };
  });

  const socialEvents = parsed.social.map((p) => ({
    id: p.id,
    timestamp: p.timestamp,
    platform: p.platform,
    username: p.username,
    loginIp: p.loginIp,
    device: p.device,
    locationTag: p.locationTag,
    caption: p.caption,
    flagged: isOffHours(p.timestamp),
    flag: isOffHours(p.timestamp) ? 'Off-hours post' : undefined,
  }));

  return { cdrEvents, ipdrEvents, bankEvents, socialEvents };
}

/**
 * Render a bank row's counterparties, falling back through every column a real
 * statement might actually populate. Returns just the txn type when nothing at all
 * is available, rather than the misleading "— → —".
 */
function bankParties(b: BankRow): string {
  const from = b.sender || b.senderAcc || b.account || '';
  const to = b.receiver || b.receiverAcc || '';
  const bits: string[] = [];
  if (b.txnType) bits.push(b.txnType);
  if (from && to) bits.push(`${from} → ${to}`);
  else if (from) bits.push(`From ${from}`);
  else if (to) bits.push(`To ${to}`);
  if (b.bankName) bits.push(b.bankName);
  return bits.length > 0 ? bits.join(' | ') : 'Counterparty not disclosed in statement';
}

function buildTimeline(parsed: ParsedSources, crypto: CryptoResolution) {
  type T = {
    source: string;
    badge: string;
    label: string;
    time: string;
    title: string;
    detail: string;
    flagged: boolean;
    flag?: string;
    star: boolean;
    _ms: number;
  };
  const t: T[] = [];

  for (const c of parsed.cdr) {
    t.push({
      source: 'CDR', badge: 'b-cdr', label: 'CDR', time: fmtTime(c.timestamp),
      title: `${c.type === 'sms' ? 'SMS' : 'Call'} ${c.from} → ${c.to}`,
      detail: `Duration: ${c.duration}s | Tower: ${c.tower}`,
      flagged: isOffHours(c.timestamp), flag: isOffHours(c.timestamp) ? 'Off-hours activity' : undefined,
      star: false, _ms: ms(c.timestamp),
    });
  }
  for (const s of parsed.ipdr) {
    t.push({
      source: 'IPDR', badge: 'b-ipdr', label: 'IPDR', time: fmtTime(s.timestamp),
      title: `IPDR Session: ${s.ip} → ${s.domain}`,
      detail: `Device: ${s.device} | IMEI: ${s.imei} | ${s.dataMB} MB`,
      flagged: /tor|vpn/i.test(s.domain), flag: /tor|vpn/i.test(s.domain) ? 'Anonymization indicator' : undefined,
      star: false, _ms: ms(s.timestamp),
    });
  }
  for (const b of parsed.bank) {
    const big = b.amount >= 100000;
    t.push({
      source: 'Bank', badge: 'b-bank', label: 'BANK', time: fmtTime(b.timestamp),
      title: `${b.type} ₹${b.amount.toLocaleString('en-IN')} — ${b.description}`,
      // Named parties first, account numbers second. Many statements carry
      // sender/receiver names but no separate sender_account/receiver_account
      // column, which rendered the whole line as a bare "— → —".
      detail: bankParties(b),
      flagged: big, flag: big ? 'Large-value transaction' : undefined,
      star: false, _ms: ms(b.timestamp),
    });
  }
  for (const p of parsed.social) {
    t.push({
      source: 'Social', badge: 'b-social', label: 'SOCIAL', time: fmtTime(p.timestamp),
      title: `${p.platform} post: "${p.caption}"${p.locationTag ? ` — ${p.locationTag}` : ''}`,
      detail: `Login IP: ${p.loginIp} | Device: ${p.device}`,
      flagged: false, star: false, _ms: ms(p.timestamp),
    });
  }
  for (const e of crypto.events) {
    const asset = e.amountBTC != null ? `${e.amountBTC} BTC` : `${e.amountETH} ETH`;
    t.push({
      source: 'Crypto', badge: 'b-crypto', label: 'CRYPTO', time: fmtTime(e.timestamp),
      title: `${asset} ${e.type} — ${e.from} → ${e.to}`,
      detail: `Hash: ${e.hash} | Exchange: ${e.exchange || '—'}`,
      flagged: e.flagged, flag: e.flag, star: e.flagged, _ms: ms(e.timestamp),
    });
  }

  return t
    .sort((a, b) => a._ms - b._ms)
    .map(({ _ms, ...rest }) => rest);
}

function buildNetwork(parsed: ParsedSources, wallet: string, suspectName: string, correlations: Correlation[]): { networkNodes: NetworkNode[]; networkEdges: NetworkEdge[] } {
  const nodes: NetworkNode[] = [];
  const edges: NetworkEdge[] = [];
  const seen = new Set<string>();
  const centerX = 400, centerY = 300, radius = 200;

  const addNode = (id: string, label: string, sublabel: string, color: string, size: number) => {
    if (seen.has(id)) return;
    seen.add(id);
    nodes.push({ id, label, sublabel, color, size, x: 0, y: 0 });
  };

  addNode('n1', suspectName || 'Suspect', 'Primary Suspect', '#EF4444', 32);

  const phones = [...new Set(parsed.cdr.map((c) => c.from))].slice(0, 3);
  phones.forEach((p, i) => {
    const id = `phone-${i}`;
    addNode(id, p, 'CDR Device', '#F87171', 22);
    edges.push({ from: 'n1', to: id, label: 'owns', dashed: false });
  });

  const receivers = [...new Set(parsed.cdr.map((c) => c.to))].slice(0, 4);
  receivers.forEach((r, i) => {
    const id = `rcv-${i}`;
    addNode(id, r, 'Contact', '#F59E0B', 18);
    edges.push({ from: phones[0] ? 'phone-0' : 'n1', to: id, label: 'called', dashed: false });
  });

  if (wallet) {
    addNode('wallet', `${wallet.slice(0, 6)}...${wallet.slice(-4)}`, 'Crypto Wallet', '#EF4444', 26);
    edges.push({ from: 'n1', to: 'wallet', label: 'owns wallet', dashed: false });
  }

  // Mule Chain Depth Detection
  // Create nodes for all accounts involved in transfers
  const bankNodes = new Set<string>();
  const transfers = new Map<string, number>(); // edgeId -> weight

  parsed.bank.forEach(b => {
    if (b.senderAcc && b.receiverAcc) {
      bankNodes.add(b.senderAcc);
      bankNodes.add(b.receiverAcc);
      const edgeId = `${b.senderAcc}_${b.receiverAcc}`;
      transfers.set(edgeId, (transfers.get(edgeId) || 0) + b.amount);
    } else if (b.account) {
      bankNodes.add(b.account);
    }
  });

  const accountArr = Array.from(bankNodes).slice(0, 6);
  accountArr.forEach((a, i) => {
    const id = `acc-${a}`;
    addNode(id, a, 'Bank Account', '#3B82F6', 20);
    // Link to suspect if it's the primary account
    if (i === 0 || a === suspectName) {
      edges.push({ from: 'n1', to: id, label: 'controls', dashed: true });
    }
  });

  // Add edges for the transfers between these accounts
  transfers.forEach((amount, edgeId) => {
    const [sender, receiver] = edgeId.split('_');
    if (accountArr.includes(sender) && accountArr.includes(receiver)) {
      edges.push({
        from: `acc-${sender}`,
        to: `acc-${receiver}`,
        label: `₹${amount.toLocaleString('en-IN')}`,
        dashed: false
      });
    }
  });

  const socials = [...new Set(parsed.social.map((s) => s.username))].slice(0, 3);
  socials.forEach((u, i) => {
    const id = `soc-${i}`;
    addNode(id, u, 'Social Account', '#06B6D4', 20);
    edges.push({ from: 'n1', to: id, label: 'linked', dashed: true });
  });

  // Add IPDR domains, particularly linking to Bank transactions if relevant
  const domains = [...new Set(parsed.ipdr.map(i => i.domain).filter(d => d && d !== ''))].slice(0, 4);
  domains.forEach((d, i) => {
    const id = `dom-${i}`;
    const isBankDomain = /bank|corp|portal|crypto/i.test(d);
    addNode(id, d, 'Web Session', isBankDomain ? '#FFB300' : '#8B5CF6', 18);
    edges.push({ from: 'n1', to: id, label: 'visited', dashed: true });
    
    // If it's a banking/corporate domain, visually link it to the first bank account
    if (isBankDomain && accountArr.length > 0) {
      edges.push({ from: id, to: `acc-${accountArr[0]}`, label: 'session trigger', dashed: true });
    }
  });

  // ── Correlation edges ──────────────────────────────────────────────────────
  // Everything above is plumbing: one row of one file produced one line. None of it
  // draws the engine's actual conclusions, so a graph built only from it shows a
  // suspect surrounded by unrelated spokes and the cross-source findings live nowhere.
  // These edges connect the entities each correlation is *about*.
  addCorrelationEdges(edges, nodes, correlations, { phones, receivers, accounts: accountArr, socials, domains, wallet });

  // Radial layout around the primary suspect.
  const others = nodes.filter((n) => n.id !== 'n1');
  const n1 = nodes.find((n) => n.id === 'n1')!;
  n1.x = centerX; n1.y = centerY;
  others.forEach((node, i) => {
    const angle = (i / Math.max(1, others.length)) * Math.PI * 2;
    node.x = Math.round(centerX + radius * Math.cos(angle));
    node.y = Math.round(centerY + radius * Math.sin(angle));
  });

  return { networkNodes: nodes, networkEdges: edges };
}

/** Which concrete graph nodes stand in for each evidence stream. */
interface NodeIndex {
  phones: string[];
  receivers: string[];
  accounts: string[];
  socials: string[];
  domains: string[];
  wallet: string;
}

/**
 * Resolve one side of a correlation's `pair` label to graph node ids, most
 * representative first. Returns [] when that stream produced no nodes — a
 * correlation over data the graph does not show must not invent an anchor for it.
 */
function nodesForStream(token: string, idx: NodeIndex): string[] {
  const t = token.toLowerCase();
  if (/blockchain|crypto|wallet/.test(t)) return idx.wallet ? ['wallet'] : [];
  if (/bank|velocity/.test(t)) return idx.accounts.map((a) => `acc-${a}`);
  if (/social/.test(t)) return idx.socials.map((_, i) => `soc-${i}`);
  if (/ipdr|session|device/.test(t)) return idx.domains.map((_, i) => `dom-${i}`);
  if (/cdr|call|tower|baseline/.test(t)) {
    return [...idx.phones.map((_, i) => `phone-${i}`), ...idx.receivers.map((_, i) => `rcv-${i}`)];
  }
  return [];
}

/** Short pill text for the SVG edge label — the full title goes in the hover tooltip. */
function edgePillLabel(c: Correlation): string {
  return `${c.confidence}% link`;
}

function addCorrelationEdges(
  edges: NetworkEdge[],
  nodes: NetworkNode[],
  correlations: Correlation[],
  idx: NodeIndex,
): void {
  const present = new Set(nodes.map((n) => n.id));
  const filter = (ids: string[]) => ids.filter((id) => present.has(id));

  for (const c of correlations) {
    const sides = c.pair.split('↔').map((s) => s.trim());
    const left = filter(nodesForStream(sides[0] ?? '', idx));
    // A single-stream finding ("Bank Velocity", "Behavioural Baseline") has no second
    // side; anchor it to the suspect, who is what the finding is actually asserting about.
    const right = sides.length > 1 ? filter(nodesForStream(sides[1], idx)) : ['n1'];
    if (!left.length || !right.length) continue;

    // Same-stream findings (CDR ↔ CDR, Bank ↔ Bank) must span two distinct nodes of
    // that stream, otherwise the edge is a self-loop the renderer cannot draw.
    let from = left[0];
    let to = right[0];
    if (from === to) {
      const alt = right.find((id) => id !== from) ?? left.find((id) => id !== to);
      if (!alt) continue;
      to = alt;
    }

    const meta = {
      kind: 'correlation' as const,
      title: `${c.title} — ${c.pair}`,
      confidence: c.confidence,
      risk: c.risk,
    };

    // Promote an existing structural edge rather than stacking a second line over it:
    // two paths between the same pair of nodes render as one thicker smear.
    const existing = edges.find(
      (e) => (e.from === from && e.to === to) || (e.from === to && e.to === from),
    );
    if (existing && existing.kind !== 'correlation') {
      Object.assign(existing, { label: edgePillLabel(c), dashed: false, ...meta });
      continue;
    }
    if (existing) continue;

    edges.push({ from, to, label: edgePillLabel(c), dashed: false, ...meta });
  }
}

function buildFindings(correlations: Correlation[]) {
  return correlations.map((c) => ({
    title: c.title,
    risk: c.risk,
    source: c.pair,
    conf: c.confidence,
    star: c.star,
    desc: c.finding,
  }));
}

function buildActions(correlations: Correlation[]): string[] {
  const acts = correlations.map((c) => c.action).filter(Boolean);
  return [...new Set(acts)];
}

export function buildDynamicCaseDocument(input: DynamicInput): CaseDocument {
  const { parsed, crypto, anomalies, wallet, suspect = {}, evidenceHashes, aiEnrichedData } = input;
  let { correlations, risk } = input;
  
  if (aiEnrichedData) {
    if (aiEnrichedData.correlations?.length > 0) {
      correlations = aiEnrichedData.correlations.map((c: any) => ({
        ...c,
        id: '',
        color: c.risk === 'CRITICAL' ? '#EF4444' : c.risk === 'HIGH' ? '#F59E0B' : '#3B82F6',
        fullWidth: c.risk === 'CRITICAL',
        star: c.risk === 'CRITICAL' || c.risk === 'HIGH'
      }));
    }
    if (aiEnrichedData.riskBreakdown?.length > 0) {
      risk = {
        ...risk,
        breakdown: aiEnrichedData.riskBreakdown,
        score: aiEnrichedData.riskBreakdown.reduce((sum, r) => sum + r.points, 0)
      };
      risk.level = risk.score >= 80 ? 'CRITICAL' : risk.score >= 50 ? 'HIGH' : risk.score >= 20 ? 'MEDIUM' : 'LOW';
      risk.listBadge = risk.score >= 50 ? 'HIGH' : risk.score >= 20 ? 'MEDIUM' : 'LOW';
    }
  }
  const { range, latest } = dateRange(parsed);
  const sourceCounts = counts(parsed, crypto);
  const { cdrEvents, ipdrEvents, bankEvents, socialEvents } = buildDynamicEvents(parsed);
  const suspectName = suspect.name || 'Unknown Suspect';

  const suspectInfo = {
    id: input.caseId,
    name: suspectName,
    alias: suspect.alias || '—',
    fir: suspect.fir || '—',
    officer: suspect.officer || '—',
    phone: suspect.phone || mostFrequent(parsed.cdr.map((c) => c.from)) || '—',
    bankAccount: suspect.bankAccount || mostFrequent(parsed.bank.map((b) => b.account)) || '—',
    walletAddress: wallet || '—',
    dateRange: range,
    riskScore: risk.score,
    riskLevel: risk.level,
    status: 'ACTIVE',
  };

  const { networkNodes, networkEdges } = buildNetwork(parsed, wallet, suspectName, correlations);

  if (aiEnrichedData) {
    if (aiEnrichedData.nodeFacts) {
      for (const node of networkNodes) {
        // Try exact match or substring match on label
        const factKey = Object.keys(aiEnrichedData.nodeFacts).find(k => node.label.includes(k) || k.includes(node.label) || k === node.id);
        if (factKey) {
          node.facts = aiEnrichedData.nodeFacts[factKey];
        }
      }
    }
    if (aiEnrichedData.networkEdgeLabels) {
      for (const edge of networkEdges) {
        const key = `${edge.from}_${edge.to}`;
        if (aiEnrichedData.networkEdgeLabels[key]) {
          edge.label = aiEnrichedData.networkEdgeLabels[key];
        }
      }
    }
  }

  return {
    caseId: input.caseId,
    createdAt: input.createdAt,
    suspectInfo,
    cdrEvents,
    ipdrEvents,
    bankEvents,
    socialEvents,
    cryptoEvents: crypto.events,
    timelineEvents: buildTimeline(parsed, crypto),
    correlations,
    networkNodes,
    networkEdges,
    findings: buildFindings(correlations),
    actions: buildActions(correlations),
    evidenceHashes,
    sourceCounts,
    anomaliesCount: anomalies.count,
    anomalyList: anomalies.anomalies,
    riskBreakdown: risk.breakdown,
    suspect: suspectName,
    date: latest,
    sources: activeSources(sourceCounts),
    risk: risk.listBadge,
    score: risk.score,
    status: 'ACTIVE',
    aiEnriched: !!aiEnrichedData,
  };
}
