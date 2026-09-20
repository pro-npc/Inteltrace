import type { APIContext } from 'astro';
import { loadEnv } from './env';

/** JSON response with no-store caching (API responses are always dynamic). */
export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      ...headers,
    },
  });
}

export function fail(message: string, status = 400, headers: Record<string, string> = {}): Response {
  return json({ error: message }, status, headers);
}

/**
 * Runtime configuration (secrets + paths).
 *
 * Kept as a function of `locals` so every existing call site is unchanged, but the
 * values now come from the local process environment rather than a Worker binding —
 * the parameter is accepted and ignored.
 */
export function getEnv(_locals?: App.Locals): Env {
  return loadEnv();
}

/** Stable, path-safe document id derived from a badge id / arbitrary key. */
export function docId(raw: string): string {
  return raw.trim().replace(/[^A-Za-z0-9._@-]/g, '_');
}

/** Best-effort client IP for the audit log. */
export function clientIp(request: Request): string {
  return (
    request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    request.headers.get('x-real-ip') ||
    'local'
  );
}

export async function readJson<T = Record<string, unknown>>(context: APIContext): Promise<T | null> {
  try {
    return (await context.request.json()) as T;
  } catch {
    return null;
  }
}
