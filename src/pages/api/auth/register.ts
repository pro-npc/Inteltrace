import type { APIRoute } from 'astro';
import { json, fail, getEnv, readJson, docId } from '../../../lib/http';
import { getDoc, setDoc } from '../../../lib/store';
import { hashPassword, generateTotpSecret, otpauthURI } from '../../../lib/auth';

export const prerender = false;

// Admin: create a real investigator account. Gated by the server SESSION_SECRET
// passed as `bootstrapKey` (only the operator knows it), so registration is not open.
export const POST: APIRoute = async (context) => {
  const env = getEnv(context.locals);
  const body = await readJson<{
    bootstrapKey?: string;
    badgeId?: string;
    email?: string;
    name?: string;
    role?: string;
    password?: string;
  }>(context);

  if (!body || body.bootstrapKey !== env.SESSION_SECRET) return fail('Forbidden', 403);

  const badgeId = (body.badgeId || '').trim();
  if (!badgeId || !body.password) return fail('badgeId and password are required', 400);

  const id = docId(badgeId);
  if (await getDoc(env, `users/${id}`)) return fail('User already exists', 409);

  const pw = await hashPassword(body.password);
  const totpSecret = generateTotpSecret();
  await setDoc(env, `users/${id}`, {
    badgeId,
    email: body.email || badgeId,
    name: body.name || badgeId,
    role: body.role || 'Investigator',
    passwordHash: pw.hash,
    passwordSalt: pw.salt,
    passwordIter: pw.iterations,
    totpSecret,
    createdAt: new Date().toISOString(),
  });

  return json({ ok: true, badgeId, totpSecret, otpauthURI: otpauthURI(totpSecret, badgeId) });
};
