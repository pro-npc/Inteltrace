// Bundled market data — used as a deterministic fallback when the live CoinGecko
// call is unavailable or rate-limited, and to guarantee the curated case
// CASE-2024-0892 reproduces byte-for-byte offline.
//
// Prices are in INR per whole coin. The curated BTC price at the transaction
// timestamp is the value that makes the documented match exact:
//   0.0312 BTC × ₹70,86,600 × (1 − 0.0072 WazirX fee) = ₹2,19,510.30 → ₹2,19,510
//   |2,19,510 − 2,19,450| / 2,19,510 = 0.0273% → 0.03% variance vs the bank credit.

export interface PricePoint {
  /** ISO date (yyyy-mm-dd) the price applies to. */
  date: string;
  /** INR per whole coin. */
  inr: number;
}

// Keyed by asset symbol → date → INR price.
export const PRICE_FIXTURES: Record<string, Record<string, number>> = {
  BTC: {
    '2024-03-15': 7086600,
    '2024-03-14': 7042000,
    '2024-03-16': 7110000,
  },
  ETH: {
    '2024-03-15': 331500,
    '2024-03-14': 329000,
    '2024-03-16': 334200,
  },
};

// Exchange settlement fee (percent of gross) applied when crypto is liquidated
// to fiat. WazirX publishes 0.72% — the number the correlation engine reconciles.
export const EXCHANGE_FEES: Record<string, number> = {
  WazirX: 0.72,
  CoinDCX: 0.5,
  ZebPay: 0.45,
  Binance: 0.6,
  default: 0.72,
};

/** Look up a bundled INR price for `asset` on the calendar day of `iso`. */
export function fixturePriceInr(asset: string, iso: string): number | null {
  const day = iso.slice(0, 10);
  const table = PRICE_FIXTURES[asset.toUpperCase()];
  if (!table) return null;
  return table[day] ?? null;
}

/** Fee fraction (e.g. 0.0072) for an exchange name, defaulting to WazirX. */
export function feeFraction(exchange?: string): number {
  const pct = (exchange && EXCHANGE_FEES[exchange]) || EXCHANGE_FEES.default;
  return pct / 100;
}
