import { loadConfig } from './config.js';
import { checkSchema, createPool, signIn, SUPPORTED_MIGRATIONS } from './docmost.js';
import { Oidc } from './oidc.js';
import { buildApp } from './server.js';

function log(entry: Record<string, unknown>): void {
  process.stdout.write(`${JSON.stringify({ time: new Date().toISOString(), ...entry })}\n`);
}

async function main(): Promise<void> {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    log({ event: 'startup', outcome: 'error', error: (err as Error).message });
    process.exit(1);
  }

  const pool = createPool(config.databaseUrl);
  pool.on('error', (err) => log({ event: 'db_pool_error', error: err.message }));

  const oidc = new Oidc({
    issuer: config.oidcIssuer,
    clientId: config.oidcClientId,
    clientSecret: config.oidcClientSecret,
    redirectUri: new URL('/sso/callback', config.appUrl).href,
    allowInsecure: config.oidcAllowInsecure,
    allowedDomains: config.allowedDomains,
  });

  const app = buildApp({
    config,
    oidc,
    db: { signIn: (input) => signIn(pool, input), checkSchema: () => checkSchema(pool) },
    log,
  });

  // Version guard at start: report loudly. The shim stays up (so /sso/healthz
  // can say why) but refuses every sign-in until the schema is supported.
  const schema = await checkSchema(pool);
  log({
    event: 'startup',
    outcome: schema.ok ? 'ok' : 'schema_unsupported',
    migration: schema.migration,
    ...(schema.ok ? {} : { error: schema.error, supported: [...SUPPORTED_MIGRATIONS] }),
    appUrl: config.appUrl.origin,
    issuer: config.oidcIssuer,
    allowedDomains: config.allowedDomains,
    port: config.port,
  });

  await app.listen({ port: config.port, host: config.host });

  const shutdown = async (signal: string) => {
    log({ event: 'shutdown', signal });
    await app.close().catch(() => undefined);
    await pool.end().catch(() => undefined);
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

void main();
