/// <reference path="../.astro/types.d.ts" />

/**
 * Runtime configuration, read from the local process environment (`.env`).
 *
 * This was previously the Cloudflare Worker binding object. IntelTrace now runs as a
 * local Node server on the investigator's machine, so there are no platform bindings:
 * every value is a plain environment variable loaded by `src/lib/env.ts`.
 */
interface Env {
  /** AES-GCM secret for the encrypted-at-rest case payload. Required in production. */
  ENCRYPTION_KEY?: string;
  /** HMAC secret for session cookies. */
  SESSION_SECRET: string;
  /** Absolute or project-relative path to the SQLite case store. */
  DATA_DIR?: string;

  GEMINI_API_KEY: string;
  ETHERSCAN_API_KEY: string;

  OMNIROUTE_API_KEY?: string;
  OMNIROUTE_BASE_URL?: string;
  OMNIROUTE_PRIMARY_MODEL?: string;
  OMNIROUTE_VALIDATOR_MODEL?: string;
}

declare namespace App {
  interface Locals {}
}
