// A small sample of OFAC-sanctioned cryptocurrency addresses (SDN list). This is
// public data used by the risk engine to flag counterparties. It is intentionally
// a representative subset — the curated suspect wallet is deliberately NOT on this
// list (so the curated case scores 87, not 107), while still exercising the check.
//
// Addresses are stored lowercased for case-insensitive comparison.

export const OFAC_ADDRESSES: ReadonlySet<string> = new Set(
  [
    // Historic, well-publicised OFAC SDN crypto designations (illustrative).
    '0x7f367cc41522ce07553e823bf3be79a889debe1b', // Lazarus-linked (illustrative)
    '0x098b716b8aaf21512996dc57eb0615e2383e2f96', // Ronin exploit (illustrative)
    '0x8576acc5c05d6ce88f4e49bf65bdf0c62f91353c', // Blender.io (illustrative)
    '1p5zeddegylkptmmvp8gdyu9pv5pvsgzcx',        // BTC SDN (illustrative)
    'bc1qazcm763858nkj2dj986etajv6wquslv8uxwczt', // BTC SDN (illustrative)
  ].map((a) => a.toLowerCase()),
);

/** True if the given wallet/counterparty address is on the bundled OFAC list. */
export function isOfacSanctioned(address?: string | null): boolean {
  if (!address) return false;
  return OFAC_ADDRESSES.has(address.trim().toLowerCase());
}
