import { defineConfig } from 'astro/config';
import tailwind from '@astrojs/tailwind';
import node from '@astrojs/node';

// https://astro.build/config
export default defineConfig({
  // Runs as a local Node server on the investigator's own machine. Case data never
  // leaves the host: storage is a local SQLite file (see src/lib/store.ts), so there
  // is no per-request CPU ceiling and no external database quota.
  //
  // Site stays static by default (near-zero-JS baseline). Only routes that opt out
  // with `export const prerender = false` (the /api/** endpoints and the data-driven
  // Results page) are rendered on the server.
  adapter: node({ mode: 'standalone' }),
  integrations: [tailwind({ applyBaseStyles: false })],
  server: { port: 3000, host: true },
  vite: {
    server: { fs: { allow: ['..'] } },
    // node:sqlite is a Node builtin with no npm package; keep Vite from trying to
    // pre-bundle it for the browser graph.
    ssr: { external: ['node:sqlite'] },
  },
});
