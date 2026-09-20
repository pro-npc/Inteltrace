// Runtime configuration for the local Node server.
//
// Replaces the Cloudflare Worker binding object that used to arrive on
// `locals.runtime.env`. Values come from the process environment, which Astro
// populates from `.env` at both dev and build time; `process.env` takes precedence so
// the standalone server can be configured by the shell that launches it.

/** Read a variable from the process env, falling back to Astro's compile-time env. */
function read(key: string): string | undefined {
  const fromProcess = typeof process !== 'undefined' ? process.env?.[key] : undefined;
  if (fromProcess !== undefined && fromProcess !== '') return fromProcess;
  const fromAstro = (import.meta.env as Record<string, unknown>)?.[key];
  return typeof fromAstro === 'string' && fromAstro !== '' ? fromAstro : undefined;
}

let cached: Env | null = null;

export function loadEnv(): Env {
  if (cached) return cached;

  const sessionSecret = read('SESSION_SECRET');
  if (!sessionSecret) {
    // Sessions are HMAC-signed; an absent secret would silently downgrade every
    // cookie to unauthenticated-but-accepted. Fail loudly at first use instead.
    throw new Error(
      'SESSION_SECRET is not set. Copy .env.example to .env and set it before starting the server.',
    );
  }

  cached = {
    ENCRYPTION_KEY: read('ENCRYPTION_KEY'),
    SESSION_SECRET: sessionSecret,
    DATA_DIR: read('DATA_DIR'),
    GEMINI_API_KEY: read('GEMINI_API_KEY') ?? '',
    ETHERSCAN_API_KEY: read('ETHERSCAN_API_KEY') ?? '',
    OMNIROUTE_API_KEY: read('OMNIROUTE_API_KEY'),
    OMNIROUTE_BASE_URL: read('OMNIROUTE_BASE_URL'),
    OMNIROUTE_PRIMARY_MODEL: read('OMNIROUTE_PRIMARY_MODEL'),
    OMNIROUTE_VALIDATOR_MODEL: read('OMNIROUTE_VALIDATOR_MODEL'),
  };
  return cached;
}

/** Reset the memo. Test-only. */
export function resetEnvCache(): void {
  cached = null;
}
