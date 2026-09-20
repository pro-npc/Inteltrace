import type { APIRoute } from 'astro';
import { json, fail, getEnv, readJson, docId } from '../../../lib/http';
import { getDoc, setDoc } from '../../../lib/store';
import { hashPassword, generateTotpSecret, otpauthURI } from '../../../lib/auth';

export const prerender = false;

// Seed the initial investigator account. Strictly gated behind server SESSION_SECRET
// as bootstrapKey (or X-Bootstrap-Key header) to prevent unauthorized account creation.
export const POST: APIRoute = async (context) => {
  const env = getEnv(context.locals);

  // Gating check
  type SeedBody = { bootstrapKey?: string; password?: string; badgeId?: string };
  const body = await readJson<SeedBody>(context).catch(() => ({}) as SeedBody);
  const headerKey = context.request.headers.get('x-bootstrap-key');
  const authKey = body?.bootstrapKey || headerKey;

  if (!env.SESSION_SECRET || authKey !== env.SESSION_SECRET) {
    return fail('Forbidden — valid bootstrap authorization key required', 403);
  }

  const badgeId = (body?.badgeId || 'inspector@cybercrime.gov.in').trim();
  const password = body?.password || 'demo_secure_2024';
  const id = docId(badgeId);

  const existing = await getDoc(env, `users/${id}`);
  if (existing) {
    return json({ seeded: false, message: 'Investigator account is already provisioned' }, 200);
  }

  const pw = await hashPassword(password);
  const totpSecret = generateTotpSecret();
  await setDoc(env, `users/${id}`, {
    badgeId,
    email: badgeId,
    name: 'Inspector S. Mehta',
    role: 'Senior Investigator',
    passwordHash: pw.hash,
    passwordSalt: pw.salt,
    passwordIter: pw.iterations,
    totpSecret,
    createdAt: new Date().toISOString(),
  });

  return json({
    seeded: true,
    badgeId,
    otpauthURI: otpauthURI(totpSecret, badgeId),
    message: 'Investigator account successfully initialized. Scan otpauth URI for MFA.',
  });
};
