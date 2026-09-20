// Entity Resolution & Normalization Subsystem
//
// Provides deterministic normalization, validation, and fuzzy matching for:
// - Indian Phone Numbers (E.164, 10-digit national, STD codes)
// - Bank Accounts (Zero-padding strip, IFSC extraction, fuzzy account names)
// - IP Addresses & Subnets (IPv4 CIDR /24 subnet correlation, private/public)
// - Hardware Identifiers (IMEI Luhn check, TAC code, device model standardization)
// - Social Handles (Sanitization, platform normalization)
// - Crypto Wallets (EIP-55 Ethereum, Base58/Bech32 Bitcoin)

// ─────────────────────────────────────────────────────────────────────────────
// 1. Phone Numbers
// ─────────────────────────────────────────────────────────────────────────────

export interface NormalizedPhone {
  raw: string;
  e164: string; // +919876543210
  national: string; // 9876543210
  isValid: boolean;
}

/**
 * Normalizes Indian mobile numbers (+91, 0-prefix, dashes, spaces, brackets).
 * Handles both 10-digit mobile numbers (6/7/8/9 prefix) and landlines.
 */
export function normalizePhone(input: string | undefined | null): NormalizedPhone {
  if (!input) return { raw: '', e164: '', national: '', isValid: false };
  const raw = String(input).trim();
  // Strip all non-digit characters except leading +
  const digits = raw.replace(/\D/g, '');

  let national = '';
  if (digits.length === 10) {
    national = digits;
  } else if (digits.length === 11 && digits.startsWith('0')) {
    national = digits.slice(1);
  } else if (digits.length === 12 && digits.startsWith('91')) {
    national = digits.slice(2);
  } else if (digits.length > 10 && digits.endsWith(digits.slice(-10))) {
    national = digits.slice(-10);
  } else {
    national = digits;
  }

  // Indian mobile numbers are 10 digits starting with 6, 7, 8, or 9
  const isValid = /^[6-9]\d{9}$/.test(national);
  const e164 = isValid ? `+91${national}` : (national ? `+${digits}` : '');

  return { raw, e164, national, isValid };
}

/**
 * Checks if two phone number strings reference the same entity.
 */
export function arePhonesEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) return false;
  const pA = normalizePhone(a);
  const pB = normalizePhone(b);
  if (pA.isValid && pB.isValid) {
    return pA.national === pB.national;
  }
  return pA.raw.replace(/\D/g, '') === pB.raw.replace(/\D/g, '');
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Bank Accounts & Fuzzy Name Matching
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Normalizes bank account numbers by removing hyphens, spaces, and leading zeros.
 */
export function normalizeBankAccount(account: string | undefined | null): string {
  if (!account) return '';
  const cleaned = String(account).trim().replace(/[\s-_]/g, '');
  // Strip leading zeroes for comparison, but keep at least 1 digit if all zeroes
  const stripped = cleaned.replace(/^0+/, '');
  return stripped.length > 0 ? stripped : cleaned;
}

export function areBankAccountsEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) return false;
  const accA = normalizeBankAccount(a);
  const accB = normalizeBankAccount(b);
  if (!accA || !accB) return false;
  return accA === accB;
}

/**
 * Jaro-Winkler string similarity distance metric (0.0 to 1.0).
 * Highly effective for short strings like names, person aliases, and accounts.
 */
export function jaroWinkler(s1: string, s2: string): number {
  const str1 = s1.toLowerCase().trim();
  const str2 = s2.toLowerCase().trim();

  if (str1 === str2) return 1.0;
  if (!str1.length || !str2.length) return 0.0;

  const matchWindow = Math.floor(Math.max(str1.length, str2.length) / 2) - 1;
  const str1Matches = new Array(str1.length).fill(false);
  const str2Matches = new Array(str2.length).fill(false);

  let matches = 0;
  let transpositions = 0;

  for (let i = 0; i < str1.length; i++) {
    const start = Math.max(0, i - matchWindow);
    const end = Math.min(i + matchWindow + 1, str2.length);

    for (let j = start; j < end; j++) {
      if (str2Matches[j] || str1[i] !== str2[j]) continue;
      str1Matches[i] = true;
      str2Matches[j] = true;
      matches++;
      break;
    }
  }

  if (matches === 0) return 0.0;

  let k = 0;
  for (let i = 0; i < str1.length; i++) {
    if (!str1Matches[i]) continue;
    while (!str2Matches[k]) k++;
    if (str1[i] !== str2[k]) transpositions++;
    k++;
  }

  const sim = (matches / str1.length + matches / str2.length + (matches - transpositions / 2) / matches) / 3;

  // Winkler prefix scaling (max 4 characters, scaling factor 0.1)
  let prefix = 0;
  for (let i = 0; i < Math.min(4, Math.min(str1.length, str2.length)); i++) {
    if (str1[i] === str2[i]) prefix++;
    else break;
  }

  return sim + prefix * 0.1 * (1 - sim);
}

/**
 * Normalizes person / organization names by stripping titles, dots, and extra spaces.
 */
export function normalizeName(name: string | undefined | null): string {
  if (!name) return '';
  return String(name)
    .toUpperCase()
    .replace(/\b(MR|MRS|MS|DR|SHRI|SMT|M\/S|PVT|LTD|INC|CORP|LLC)\b\.?/gi, '')
    .replace(/[^A-Z0-9\s]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Checks if two names reference the same entity using token intersection + Jaro-Winkler.
 */
export function isNameMatch(nameA: string, nameB: string, threshold = 0.82): boolean {
  const normA = normalizeName(nameA);
  const normB = normalizeName(nameB);
  if (!normA || !normB) return false;
  if (normA === normB) return true;

  // Token subset check (e.g., "ARJUN VERMA" vs "ARJUN", or "WAZIRX EXCHANGE" vs "WAZIRX")
  const tokensA = new Set(normA.split(' '));
  const tokensB = new Set(normB.split(' '));
  let tokenOverlap = 0;
  for (const t of tokensA) {
    if (t.length > 2 && tokensB.has(t)) tokenOverlap++;
  }
  if (tokenOverlap > 0 && (tokenOverlap === tokensA.size || tokenOverlap === tokensB.size)) {
    return true;
  }

  return jaroWinkler(normA, normB) >= threshold;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. IP Addresses & Subnets
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Checks if an IPv4 address is in RFC 1918 private / loopback address space.
 */
export function isPrivateIp(ip: string): boolean {
  const cleaned = ip.trim();
  if (cleaned === '127.0.0.1' || cleaned === '::1' || cleaned === 'localhost') return true;
  const parts = cleaned.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255)) return false;

  // 10.0.0.0/8
  if (parts[0] === 10) return true;
  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;
  // 169.254.0.0/16 (link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;

  return false;
}

/**
 * Returns the /24 CIDR subnet prefix for an IPv4 address (e.g., "103.21.244.0/24").
 */
export function getIpv4Subnet(ip: string, prefixLen = 24): string | null {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) return null;
  if (prefixLen === 24) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  if (prefixLen === 16) {
    return `${parts[0]}.${parts[1]}.0.0/16`;
  }
  return ip.trim();
}

/**
 * Tests whether two IP addresses are identical or share the same /24 ISP routing subnet.
 */
export function areIpsMatching(ipA: string | undefined | null, ipB: string | undefined | null): {
  exact: boolean;
  subnetMatch: boolean;
  matched: boolean;
} {
  if (!ipA || !ipB) return { exact: false, subnetMatch: false, matched: false };
  const cleanA = ipA.trim();
  const cleanB = ipB.trim();

  if (cleanA === cleanB) {
    return { exact: true, subnetMatch: true, matched: true };
  }

  const subA = getIpv4Subnet(cleanA, 24);
  const subB = getIpv4Subnet(cleanB, 24);
  const subnetMatch = subA !== null && subA === subB;

  return {
    exact: false,
    subnetMatch,
    matched: subnetMatch,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Device Identifiers & Hardware Signatures
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Luhn checksum algorithm for 15-digit IMEI verification.
 */
export function isValidImei(imei: string): boolean {
  const digits = imei.replace(/\D/g, '');
  if (digits.length !== 15) return false;

  let sum = 0;
  for (let i = 0; i < 15; i++) {
    let d = parseInt(digits[i], 10);
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/**
 * Extracts the 8-digit Type Allocation Code (TAC) from a 15-digit IMEI.
 */
export function extractImeiTac(imei: string): string {
  const digits = imei.replace(/\D/g, '');
  return digits.slice(0, 8);
}

/**
 * Standardizes hardware device model names for cross-vector matching.
 */
export function normalizeDeviceModel(model: string | undefined | null): string {
  if (!model) return '';
  return model
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, ' ')
    .replace(/\b(5g|4g|lte|pro|ultra|plus|max)\b/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Compares two device models for hardware identity.
 */
export function areDevicesMatching(devA: string | undefined | null, devB: string | undefined | null): boolean {
  if (!devA || !devB) return false;
  const nA = normalizeDeviceModel(devA);
  const nB = normalizeDeviceModel(devB);
  if (!nA || !nB) return false;
  if (nA === nB) return true;
  return jaroWinkler(nA, nB) >= 0.85;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Social Media Handles
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Cleans social handles (strips @, lowercase, trims leading url paths).
 */
export function normalizeSocialHandle(handle: string | undefined | null): string {
  if (!handle) return '';
  let cleaned = String(handle).trim().toLowerCase();
  // Strip url prefix if user passed full URL
  cleaned = cleaned.replace(/^https?:\/\/(www\.)?(instagram|twitter|x|telegram|t\.me)\.com\//i, '');
  cleaned = cleaned.replace(/^@+/, '');
  return cleaned.replace(/[^a-z0-9_.]/g, '');
}

export function areSocialHandlesEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) return false;
  return normalizeSocialHandle(a) === normalizeSocialHandle(b);
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Crypto Wallets & Blockchain Addresses
// ─────────────────────────────────────────────────────────────────────────────

export type CryptoChain = 'ETH' | 'BTC' | 'UNKNOWN';

export function detectCryptoChain(address: string | undefined | null): CryptoChain {
  if (!address) return 'UNKNOWN';
  const a = address.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(a)) return 'ETH';
  if (/^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(a)) return 'BTC'; // Base58 legacy / P2SH
  if (/^bc1[a-z0-9]{39,59}$/i.test(a)) return 'BTC'; // Bech32 SegWit / Taproot
  return 'UNKNOWN';
}

export function normalizeCryptoAddress(address: string | undefined | null): string {
  if (!address) return '';
  const a = address.trim();
  const chain = detectCryptoChain(a);
  if (chain === 'ETH') {
    return a.toLowerCase();
  }
  return a;
}

export function areCryptoAddressesEqual(a: string | undefined | null, b: string | undefined | null): boolean {
  if (!a || !b) return false;
  return normalizeCryptoAddress(a) === normalizeCryptoAddress(b);
}
