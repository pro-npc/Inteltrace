// Blockchain + price resolution with a deterministic fixture fallback.
//
// Live sources (all free / keyless except Etherscan):
//   • Etherscan   — Ethereum (0x…) address tx history      (needs ETHERSCAN_API_KEY)
//   • Blockchain.info — Bitcoin address tx history          (keyless)
//   • CoinGecko   — historical INR price at a timestamp     (keyless)
//
// Curated case CASE-2024-0892 reproduces byte-for-byte. Known wallets
// resolve entirely from bundled fixtures — deterministic and offline-safe —
// while arbitrary uploads query live sources with graceful local fallbacks.

import { fixturePriceInr, feeFraction } from './fixtures/market';
import { fixtureTxFor, type ChainTx } from './fixtures/tx';
import { normalizeCryptoAddress, detectCryptoChain } from './entities';
import type { BankRow } from './csv';

const FETCH_TIMEOUT_MS = 6000;
const MATCH_TOLERANCE = 0.02; // 2% tolerance per prototype.md

/** A crypto event in the exact shape src/data/mockInvestigation.ts uses. */
export interface CryptoEvent {
  id: string;
  timestamp: string;
  type: 'RECEIVE' | 'SEND';
  hash: string; // display hash (0x3a9f...d821)
  fullHash: string; // full hash for the report / §65B
  from: string;
  to: string;
  amountBTC: number | null;
  amountETH: number | null;
  exchange: string | null;
  priceAtTime: number; // INR per whole coin
  expectedFiat: number;
  actualFiat: number;
  variance: number; // percent, 2dp
  flagged: boolean;
  flag?: string;
}

export interface CryptoResolution {
  events: CryptoEvent[];
  /** Whether the blockchain↔bank signature matched within tolerance. */
  matched: boolean;
  /** 'fixture' for curated/known wallets or on fallback; 'live' otherwise. */
  source: 'fixture' | 'live';
}

export interface CryptoMatchResult {
  expectedFiat: number;
  actualFiat: number;
  variance: number;
  matched: boolean;
  layeredCount: number;
  matchedRows?: BankRow[];
}

async function fetchWithTimeout(url: string, ms = FETCH_TIMEOUT_MS): Promise<Response | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { signal: ctrl.signal, headers: { accept: 'application/json' } });
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** CoinGecko historical INR price for an asset on the calendar day of `iso`. */
export async function priceAtLive(asset: string, iso: string): Promise<number | null> {
  const id = asset.toUpperCase() === 'ETH' ? 'ethereum' : 'bitcoin';
  const day = iso.slice(0, 10); // yyyy-mm-dd
  const [y, m, d] = day.split('-');
  if (!y || !m || !d) return null;
  const url = `https://api.coingecko.com/api/v3/coins/${id}/history?date=${d}-${m}-${y}&localization=false`;
  const res = await fetchWithTimeout(url);
  if (!res || !res.ok) return null;
  try {
    const data: any = await res.json();
    const inr = data?.market_data?.current_price?.inr;
    return typeof inr === 'number' ? inr : null;
  } catch {
    return null;
  }
}

/** Best-effort live transaction lookup for an arbitrary wallet. */
async function fetchTxLive(wallet: string, etherscanKey?: string): Promise<ChainTx | null> {
  const w = wallet.trim();
  const chain = detectCryptoChain(w);

  if (chain === 'ETH') {
    if (!etherscanKey) return null;
    const url = `https://api.etherscan.io/api?module=account&action=txlist&address=${w}&startblock=0&endblock=99999999&page=1&offset=10&sort=desc&apikey=${etherscanKey}`;
    const res = await fetchWithTimeout(url);
    if (!res || !res.ok) return null;
    try {
      const data: any = await res.json();
      const list: any[] = Array.isArray(data?.result) ? data.result : [];
      // Prefer the most recent incoming transfer.
      const incoming = list.find((t) => (t.to || '').toLowerCase() === w.toLowerCase()) || list[0];
      if (!incoming) return null;
      const amountEth = Number(incoming.value) / 1e18;
      return {
        hash: incoming.hash,
        displayHash: `${incoming.hash.slice(0, 6)}...${incoming.hash.slice(-4)}`,
        type: (incoming.to || '').toLowerCase() === w.toLowerCase() ? 'RECEIVE' : 'SEND',
        from: incoming.from,
        to: incoming.to,
        asset: 'ETH',
        amount: amountEth,
        timestamp: new Date(Number(incoming.timeStamp) * 1000).toISOString(),
        confirmations: Number(incoming.confirmations) || undefined,
      };
    } catch {
      return null;
    }
  }

  // Bitcoin address (base58 / bech32) via keyless Blockchain.info.
  if (chain === 'BTC') {
    const url = `https://blockchain.info/rawaddr/${encodeURIComponent(w)}?limit=1`;
    const res = await fetchWithTimeout(url);
    if (!res || !res.ok) return null;
    try {
      const data: any = await res.json();
      const tx = data?.txs?.[0];
      if (!tx) return null;
      const received = (tx.out || []).reduce((s: number, o: any) => s + (o.value || 0), 0) / 1e8;
      return {
        hash: tx.hash,
        displayHash: `${tx.hash.slice(0, 6)}...${tx.hash.slice(-4)}`,
        type: 'RECEIVE',
        from: '(multiple inputs)',
        to: w,
        asset: 'BTC',
        amount: received,
        timestamp: new Date((tx.time || 0) * 1000).toISOString(),
      };
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Expected fiat = amount × price × (1 − fee); variance = |exp − act| / exp.
 * Reconciles crypto liquations across single or multi-tranche bank credits within 48h.
 */
export function computeCryptoMatch(
  amount: number,
  priceInr: number,
  bankRows: BankRow[],
  txTimestamp: string,
  exchange?: string,
): CryptoMatchResult {
  const expected = amount * priceInr * (1 - feeFraction(exchange));
  const expectedFiat = Math.round(expected);

  const txTime = new Date(txTimestamp).getTime();
  const WINDOW_48H = 48 * 3600 * 1000;

  // Filter eligible credit rows within 48h forward of transaction timestamp
  const eligibleCredits = bankRows.filter((b) => {
    if (b.type !== 'CREDIT') return false;
    const bTime = new Date(b.timestamp).getTime();
    return bTime >= txTime && bTime <= txTime + WINDOW_48H;
  });

  // Check 1: Dedicated exchange-tagged credits (e.g. description or sender contains WazirX/CoinDCX)
  const exchangeRegex = exchange ? new RegExp(exchange, 'i') : /(wazirx|coindcx|zebpay|binance|crypto|vda)/i;
  const exchangeCredits = eligibleCredits.filter((b) =>
    exchangeRegex.test(b.description || '') ||
    exchangeRegex.test(b.sender || '') ||
    exchangeRegex.test(b.bankName || '')
  );

  let actualFiat = 0;
  let layeredCount = 0;
  let matchedRows: BankRow[] = [];

  if (exchangeCredits.length > 0) {
    actualFiat = exchangeCredits.reduce((s, b) => s + b.amount, 0);
    layeredCount = exchangeCredits.length;
    matchedRows = exchangeCredits;
  } else if (eligibleCredits.length > 0) {
    // Check 2: Try single exact credit match within tolerance
    const singleMatch = eligibleCredits.find((b) => {
      const v = expectedFiat > 0 ? Math.abs(expectedFiat - b.amount) / expectedFiat : 1;
      return v < MATCH_TOLERANCE;
    });

    if (singleMatch) {
      actualFiat = singleMatch.amount;
      layeredCount = 1;
      matchedRows = [singleMatch];
    } else {
      // Check 3: Sliding window sum of all credits within 24h
      const WINDOW_24H = 24 * 3600 * 1000;
      const credits24h = eligibleCredits.filter((b) => {
        const bTime = new Date(b.timestamp).getTime();
        return bTime >= txTime && bTime <= txTime + WINDOW_24H;
      });
      actualFiat = credits24h.reduce((s, b) => s + b.amount, 0);
      layeredCount = credits24h.length;
      matchedRows = credits24h;
    }
  }

  const variance = expectedFiat > 0 ? Math.abs(expectedFiat - actualFiat) / expectedFiat : 1;
  const variancePct = Math.round(variance * 100 * 100) / 100; // percent, 2dp

  return {
    expectedFiat,
    actualFiat,
    variance: variancePct,
    matched: variance < MATCH_TOLERANCE,
    layeredCount,
    matchedRows,
  };
}

/**
 * Resolve the crypto leg of a case.
 * @param wallet     suspect wallet address
 * @param bankRows   array of bank CSV rows to reconcile against
 * @param exchange   exchange name for the fee table (default WazirX)
 * @param etherscanKey optional key for live Ethereum reads
 */
export async function resolveCrypto(
  wallet: string,
  bankRows: BankRow[],
  exchange = 'WazirX',
  etherscanKey?: string,
): Promise<CryptoResolution> {
  const normWallet = normalizeCryptoAddress(wallet);
  const known = fixtureTxFor(normWallet);
  const tx = known.length ? known[0] : await fetchTxLive(normWallet, etherscanKey);

  if (!tx) {
    return { events: [], matched: false, source: known.length ? 'fixture' : 'live' };
  }

  let priceInr: number | null = null;
  let source: 'fixture' | 'live' = 'fixture';
  if (known.length) {
    priceInr = fixturePriceInr(tx.asset, tx.timestamp);
  } else {
    priceInr = await priceAtLive(tx.asset, tx.timestamp);
    source = priceInr != null ? 'live' : 'fixture';
    if (priceInr == null) priceInr = fixturePriceInr(tx.asset, tx.timestamp);
  }

  if (priceInr == null) {
    return { events: [], matched: false, source };
  }

  const { expectedFiat, actualFiat, variance, matched, layeredCount } = computeCryptoMatch(
    tx.amount,
    priceInr,
    bankRows,
    tx.timestamp,
    tx.exchange || exchange,
  );

  const isBtc = tx.asset === 'BTC';
  const event: CryptoEvent = {
    id: 'cry-01',
    timestamp: tx.timestamp,
    type: tx.type,
    hash: tx.displayHash,
    fullHash: tx.hash,
    from: tx.from,
    to: tx.to,
    amountBTC: isBtc ? tx.amount : null,
    amountETH: isBtc ? null : tx.amount,
    exchange: tx.exchange || exchange,
    priceAtTime: priceInr,
    expectedFiat,
    actualFiat,
    variance,
    flagged: matched,
    flag: matched
      ? `★ Layered Blockchain ↔ Bank MATCH: ${tx.amount} ${tx.asset} × ₹${priceInr.toLocaleString('en-IN')} − ${(feeFraction(tx.exchange || exchange) * 100).toFixed(2)}% ${tx.exchange || exchange} fee = ₹${expectedFiat.toLocaleString('en-IN')}. Found ${layeredCount} credit(s) within 24h summing to ₹${actualFiat.toLocaleString('en-IN')} (${variance}% variance).`
      : undefined,
  };

  return { events: [event], matched, source };
}
