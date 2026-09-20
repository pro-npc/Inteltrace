import { createHmac } from 'crypto';

function base32ToBuffer(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of base32) {
    const val = alphabet.indexOf(char.toUpperCase());
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  bits = bits.slice(0, Math.floor(bits.length / 8) * 8);
  const bytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

const secret = (process.argv[2] || process.env.TOTP_SECRET || '').trim();
if (!secret) {
  console.error('Usage: node generate_totp.mjs <BASE32_SECRET> or set TOTP_SECRET env var');
  process.exit(1);
}

const time = Math.floor(Date.now() / 1000 / 30);
const buf = Buffer.alloc(8);
buf.writeBigInt64BE(BigInt(time));
const hmac = createHmac('sha1', base32ToBuffer(secret)).update(buf).digest();
const offset = hmac[hmac.length - 1] & 0x0f;
const code = (hmac.readUInt32BE(offset) & 0x7fffffff) % 1000000;
console.log("Current TOTP Code:", code.toString().padStart(6, '0'));
