// Bundled blockchain-transaction fixtures. Used when the live chain API
// (Etherscan / Blockchain.info) is unavailable, and to guarantee the curated
// wallet resolves to the exact transaction behind CASE-2024-0892.
//
// The curated record mirrors src/data/mockInvestigation.ts (cryptoEvents[0]):
// 0.0312 "BTC" received by the suspect wallet at 2024-03-15T10:58:00 from an
// anonymous counterparty, liquidated via WazirX.

export interface ChainTx {
  /** Full transaction hash. */
  hash: string;
  /** Short display hash used in the UI (matches the curated view-model). */
  displayHash: string;
  /** RECEIVE | SEND from the suspect wallet's perspective. */
  type: 'RECEIVE' | 'SEND';
  from: string;
  to: string;
  /** Asset symbol as surfaced in the case (curated case labels it BTC). */
  asset: 'BTC' | 'ETH';
  amount: number;
  /** ISO timestamp of the transaction. */
  timestamp: string;
  /** Exchange used for the fiat off-ramp, if known. */
  exchange?: string;
  /** Confirmation depth at time of capture. */
  confirmations?: number;
}

// Keyed by lowercased wallet address.
export const TX_FIXTURES: Record<string, ChainTx[]> = {
  '0x71c7656ec7ab88b098defb751b7401b5f6d8976f': [
    {
      hash: '0x3a9f5c1e7b2d4088a6f0c39e51d47a2b8c9e0f1a2b3c4d5e6f708192a3b4d821',
      displayHash: '0x3a9f...d821',
      type: 'RECEIVE',
      from: '0xAnonymousWallet',
      to: '0x71C7656EC7ab88b098defB751B7401B5f6d8976F',
      asset: 'BTC',
      amount: 0.0312,
      timestamp: '2024-03-15T10:58:00',
      exchange: 'WazirX',
      confirmations: 18,
    },
  ],
};

/** Return bundled transactions for a wallet address, or an empty array. */
export function fixtureTxFor(wallet: string): ChainTx[] {
  return TX_FIXTURES[wallet.trim().toLowerCase()] ?? [];
}
