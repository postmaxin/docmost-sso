// HTTP routes. Built as a factory with injected dependencies for testing.

import Fastify, { type FastifyInstance, type FastifyReply } from 'fastify';
import cookie from '@fastify/cookie';
import { checkClaims, refusalMessage } from './claims.js';
import { clientIp } from './client-ip.js';
import type { Config } from './config.js';
import { deviceName } from './device-name.js';
import { RefusedError, type SchemaStatus, type SignInInput, type SignInResult } from './docmost.js';
import { FLOW_COOKIE, FLOW_TTL_SECONDS, deriveFlowKey, openFlow, sealFlow, type FlowState } from './flow-cookie.js';
import type { IdClaims } from './claims.js';
import { errorPage, loginPage } from './pages.js';
import { safeReturnTo } from './return-to.js';
import { AUTH_COOKIE, authCookieAttributes, signAccessToken } from './token.js';

export interface Deps {
  config: Config;
  oidc: {
    begin(returnTo: string): Promise<{ url: URL; flow: FlowState }>;
    complete(callbackUrl: URL, flow: FlowState): Promise<IdClaims>;
  };
  db: {
    signIn(input: SignInInput): Promise<SignInResult>;
    checkSchema(): Promise<SchemaStatus>;
  };
  log: (entry: Record<string, unknown>) => void;
}

const SCHEMA_CACHE_MS = 30_000;

export function buildApp(deps: Deps): FastifyInstance {
  const { config, oidc, db, log } = deps;
  const flowKey = deriveFlowKey(config.appSecret);
  const secure = config.appUrl.protocol === 'https:';
  const redirectUri = new URL('/sso/callback', config.appUrl);

  // No Fastify request logging: callback URLs carry authorization codes.
  const app = Fastify({
    logger: false,
    trustProxy: config.trustProxy,
    bodyLimit: 1024,
  });
  void app.register(cookie);

  // Schema guard, cached briefly so sign-in doesn't hit the DB twice per request.
  let schemaCache: { at: number; status: SchemaStatus } | undefined;
  async function schemaOk(): Promise<SchemaStatus> {
    const now = Date.now();
    if (schemaCache && schemaCache.status.ok && now - schemaCache.at < SCHEMA_CACHE_MS) {
      return schemaCache.status;
    }
    const status = await db.checkSchema();
    schemaCache = { at: now, status };
    return status;
  }

  app.addHook('onSend', async (_req, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    reply.header('X-Frame-Options', 'DENY');
    reply.header(
      'Content-Security-Policy',
      "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    );
  });

  function html(reply: FastifyReply, status: number, body: string) {
    return reply.code(status).type('text/html; charset=utf-8').send(body);
  }

  function unavailable(reply: FastifyReply) {
    return html(
      reply,
      503,
      errorPage('Sign-in unavailable', 'Sign-in is temporarily unavailable. Please try again later.'),
    );
  }

  /** Docmost's client sends `?redirect=`; `returnTo` is accepted as an alias. */
  function requestedReturnTo(q: Record<string, unknown>): string {
    return safeReturnTo(q.redirect ?? q.returnTo, config.appUrl, config.defaultReturnTo);
  }

  function startHref(returnTo: string): string {
    return returnTo === config.defaultReturnTo
      ? '/sso/start'
      : `/sso/start?redirect=${encodeURIComponent(returnTo)}`;
  }

  app.get('/sso/login', async (req, reply) => {
    const q = req.query as Record<string, unknown>;
    const returnTo = requestedReturnTo(q);
    if (q.auto === '1') return reply.redirect(startHref(returnTo), 302);
    const notice = q.logout === '1' ? 'You have been signed out.' : undefined;
    return html(reply, 200, loginPage(startHref(returnTo), config.providerName, notice));
  });

  app.get('/sso/start', async (req, reply) => {
    const returnTo = requestedReturnTo(req.query as Record<string, unknown>);
    const schema = await schemaOk();
    if (!schema.ok) {
      log({ event: 'signin', outcome: 'error', reason: 'schema_unsupported', migration: schema.migration });
      return unavailable(reply);
    }
    let begun: { url: URL; flow: FlowState };
    try {
      begun = await oidc.begin(returnTo);
    } catch (err) {
      log({ event: 'signin', outcome: 'error', reason: 'oidc_discovery_failed', error: errSummary(err) });
      return unavailable(reply);
    }
    reply.setCookie(FLOW_COOKIE, await sealFlow(begun.flow, flowKey), {
      httpOnly: true,
      secure,
      // lax: the cookie must accompany the top-level GET redirect back from the IdP.
      sameSite: 'lax',
      path: '/sso/',
      maxAge: FLOW_TTL_SECONDS,
    });
    return reply.redirect(begun.url.href, 302);
  });

  app.get('/sso/callback', async (req, reply) => {
    const q = req.query as Record<string, unknown>;
    const flowRaw = req.cookies[FLOW_COOKIE];
    reply.clearCookie(FLOW_COOKIE, { path: '/sso/', httpOnly: true, secure, sameSite: 'lax' });
    const ip = clientIp(req.ip);

    if (typeof q.error === 'string') {
      log({ event: 'signin', outcome: 'refused', reason: 'idp_error', idpError: q.error.slice(0, 64), ip });
      return html(reply, 401, errorPage('Sign-in cancelled', 'Sign-in was cancelled or denied by the identity provider.'));
    }

    const flow = await openFlow(flowRaw, flowKey);
    if (!flow) {
      log({ event: 'signin', outcome: 'refused', reason: 'flow_missing_or_expired', ip });
      return html(reply, 400, errorPage('Sign-in expired', 'Your sign-in attempt expired or was started in another browser. Please try again.'));
    }

    // Rebuild the callback URL from APP_URL, never from Host/X-Forwarded-* headers.
    const callbackUrl = new URL(redirectUri);
    const rawQuery = req.raw.url?.split('?')[1];
    if (rawQuery) callbackUrl.search = rawQuery;

    let claims: IdClaims;
    try {
      claims = await oidc.complete(callbackUrl, flow);
    } catch (err) {
      log({ event: 'signin', outcome: 'refused', reason: 'token_validation_failed', error: errSummary(err), ip });
      return html(reply, 401, errorPage('Sign-in failed', 'We could not verify your sign-in. Please try again.'));
    }

    const admission = checkClaims(claims, config.allowedDomains);
    if (!admission.ok) {
      log({ event: 'signin', outcome: 'refused', reason: admission.reason, email: admission.email, ip });
      return html(reply, 403, errorPage('Access denied', refusalMessage(admission.reason, config.allowedDomains)));
    }

    const schema = await schemaOk();
    if (!schema.ok) {
      log({ event: 'signin', outcome: 'error', reason: 'schema_unsupported', email: admission.email, migration: schema.migration });
      return unavailable(reply);
    }

    let result: SignInResult;
    try {
      result = await db.signIn({
        email: admission.email,
        name: admission.name,
        deviceName: deviceName(req.headers['user-agent']),
        ipAddress: ip,
        sessionTtlMs: config.sessionTtlMs,
      });
    } catch (err) {
      if (err instanceof RefusedError) {
        log({ event: 'signin', outcome: 'refused', reason: err.reason, email: admission.email, userId: err.userId, ip });
        const msg =
          err.reason === 'account_disabled'
            ? 'Your account has been deactivated. Ask a workspace admin to restore it.'
            : 'The workspace is not set up yet. Ask an admin.';
        return html(reply, 403, errorPage('Access denied', msg));
      }
      log({ event: 'signin', outcome: 'error', reason: 'database_error', email: admission.email, error: errSummary(err), ip });
      return unavailable(reply);
    }

    const token = await signAccessToken(
      { userId: result.userId, email: result.email, workspaceId: result.workspaceId, sessionId: result.sessionId },
      config.appSecret,
      config.sessionTtlMs,
    );
    reply.setCookie(AUTH_COOKIE, token, authCookieAttributes(config.appUrl, result.expiresAt));
    log({
      event: 'signin',
      outcome: 'success',
      email: result.email,
      userId: result.userId,
      sessionId: result.sessionId,
      created: result.created,
      ip,
    });
    return reply.redirect(safeReturnTo(flow.returnTo, config.appUrl, config.defaultReturnTo), 302);
  });

  app.get('/sso/healthz', async (_req, reply) => {
    const status = await db.checkSchema();
    schemaCache = { at: Date.now(), status };
    if (status.ok) return reply.code(200).send({ status: 'ok', migration: status.migration });
    return reply.code(503).send({ status: 'unavailable', error: status.error, migration: status.migration });
  });

  app.setNotFoundHandler((_req, reply) => html(reply, 404, errorPage('Not found', 'There is nothing here.')));
  app.setErrorHandler((err, _req, reply) => {
    log({ event: 'http_error', error: errSummary(err) });
    const status = (err as { statusCode?: number }).statusCode;
    const code = typeof status === 'number' && status >= 400 && status < 500 ? status : 500;
    return html(reply, code, errorPage('Something went wrong', 'Please try signing in again.'));
  });

  return app;
}

/** Error summary for logs: class, code and message only (no stacks, no bodies). */
export function errSummary(err: unknown): string {
  if (err instanceof Error) {
    const code = (err as { code?: unknown }).code;
    return `${err.name}${typeof code === 'string' ? `[${code}]` : ''}: ${err.message}`.slice(0, 300);
  }
  return 'unknown error';
}
