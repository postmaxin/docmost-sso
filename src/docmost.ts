// Everything the shim writes to or reads from Docmost's database.
//
// The behaviour mirrors Docmost v0.96.0 (reimplemented, not copied):
//  - new user = SignupService.signup: users row (lower-cased email, bcrypt
//    password hash, locale en-US, last_login_at now, the workspace's default
//    page edit mode in settings), role = workspaces.default_role
//    (WorkspaceService.addUserToWorkspace), membership of the workspace's
//    `is_default` group (GroupUserRepo.addUserToDefaultGroup), one transaction;
//  - sign-in = AuthService.login + SessionService.createSessionAndToken:
//    users.last_login_at = now, a user_sessions row (user_id, workspace_id,
//    device_name, ip_address, expires_at = now + JWT_TOKEN_EXPIRES_IN);
//  - disabled user = deactivated_at or deleted_at set (isUserDisabled);
//  - the workspace = the oldest row in `workspaces` (self-hosted DomainMiddleware).

import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import pg from 'pg';
import { parse as parseConnectionString } from 'pg-connection-string';

/**
 * Newest Kysely migration names the shim has been tested against. A Docmost
 * upgrade that adds a migration makes the shim refuse to serve until the new
 * version has been tested and its newest migration added here.
 */
export const SUPPORTED_MIGRATIONS: ReadonlySet<string> = new Set([
  // Docmost v0.96.0
  '20260904T171920-public-spaces',
]);

/** Kysely's default migration table (Docmost does not override it). */
const MIGRATION_TABLE = 'kysely_migration';

export class RefusedError extends Error {
  constructor(
    readonly reason: 'account_disabled' | 'no_workspace' | 'no_default_group',
    readonly userId?: string,
  ) {
    super(reason);
  }
}

export function createPool(databaseUrl: string): pg.Pool {
  // Interpret sslmode/sslrootcert with libpq semantics (pg-connection-string's
  // libpq-compat mode): `disable`/absent = no TLS, `require` = encrypted but
  // unverified, `verify-ca` = chain verified against sslrootcert, `verify-full`
  // = chain and host name verified. Mount the CA file into the container and
  // point sslrootcert at it.
  const hasCompat = /[?&]uselibpqcompat=/i.test(databaseUrl);
  const cfg = parseConnectionString(databaseUrl, hasCompat ? {} : { useLibpqCompat: true });
  return new pg.Pool({
    ...(cfg as pg.PoolConfig),
    max: 5,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30_000,
    statement_timeout: 10_000,
    application_name: 'docmost-sso',
  });
}

export type SchemaStatus =
  | { ok: true; migration: string }
  | { ok: false; migration: string | null; error: string };

export async function checkSchema(pool: pg.Pool): Promise<SchemaStatus> {
  try {
    const r = await pool.query<{ name: string }>(
      `SELECT name FROM ${MIGRATION_TABLE} ORDER BY name DESC LIMIT 1`,
    );
    const migration = r.rows[0]?.name ?? null;
    if (migration && SUPPORTED_MIGRATIONS.has(migration)) return { ok: true, migration };
    return { ok: false, migration, error: 'unsupported Docmost schema version' };
  } catch (err) {
    // Never echo driver errors to clients; they may include host names.
    return { ok: false, migration: null, error: `database check failed (${errCode(err)})` };
  }
}

function errCode(err: unknown): string {
  const code = (err as { code?: unknown })?.code;
  return typeof code === 'string' ? code : 'error';
}

export interface SignInInput {
  email: string; // already lower-cased and admitted
  name: string | undefined;
  deviceName: string | null;
  ipAddress: string | null;
  sessionTtlMs: number;
}

export interface SignInResult {
  userId: string;
  email: string;
  workspaceId: string;
  sessionId: string;
  expiresAt: Date;
  created: boolean;
}

/** Find or create the user and open a session, in one transaction. */
export async function signIn(pool: pg.Pool, input: SignInInput): Promise<SignInResult> {
  // Hash outside the transaction (bcrypt cost 12, as Docmost) so we don't hold
  // locks while hashing. Nobody ever learns the random secret: the password is unusable.
  const unusablePasswordHash = await bcrypt.hash(randomBytes(32).toString('base64url'), 12);
  try {
    return await signInTx(pool, input, unusablePasswordHash);
  } catch (err) {
    // Two first-time sign-ins racing: the loser hits the unique constraint
    // on (email, workspace_id). Retry once; the user now exists.
    if (errCode(err) === '23505') return signInTx(pool, input, unusablePasswordHash);
    throw err;
  }
}

async function signInTx(
  pool: pg.Pool,
  input: SignInInput,
  unusablePasswordHash: string,
): Promise<SignInResult> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const ws = await client.query<{ id: string; default_role: string; settings: unknown }>(
      'SELECT id, default_role, settings FROM workspaces ORDER BY created_at ASC LIMIT 1',
    );
    const workspace = ws.rows[0];
    if (!workspace) throw new RefusedError('no_workspace');

    const existing = await client.query<{
      id: string;
      email: string;
      deactivated_at: Date | null;
      deleted_at: Date | null;
    }>(
      `SELECT id, email, deactivated_at, deleted_at FROM users
        WHERE LOWER(email) = LOWER($1) AND workspace_id = $2
        LIMIT 1`,
      [input.email, workspace.id],
    );

    let userId: string;
    let email: string;
    let created = false;
    const user = existing.rows[0];
    if (user) {
      if (user.deactivated_at || user.deleted_at) {
        throw new RefusedError('account_disabled', user.id);
      }
      userId = user.id;
      email = user.email;
      await client.query(
        'UPDATE users SET last_login_at = now() WHERE id = $1 AND workspace_id = $2',
        [userId, workspace.id],
      );
    } else {
      const group = await client.query<{ id: string }>(
        'SELECT id FROM groups WHERE is_default = true AND workspace_id = $1 LIMIT 1',
        [workspace.id],
      );
      const groupId = group.rows[0]?.id;
      if (!groupId) throw new RefusedError('no_default_group');

      const pageEditMode = defaultPageEditMode(workspace.settings);
      const settings = pageEditMode ? JSON.stringify({ preferences: { pageEditMode } }) : null;
      const name = input.name || input.email.split('@')[0]!.toLowerCase();

      const ins = await client.query<{ id: string; email: string }>(
        `INSERT INTO users
           (name, email, password, locale, role, workspace_id, last_login_at,
            email_verified_at, settings)
         VALUES ($1, $2, $3, 'en-US', $4, $5, now(), now(), $6::jsonb)
         RETURNING id, email`,
        [name, input.email, unusablePasswordHash, workspace.default_role, workspace.id, settings],
      );
      userId = ins.rows[0]!.id;
      email = ins.rows[0]!.email;
      await client.query('INSERT INTO group_users (user_id, group_id) VALUES ($1, $2)', [
        userId,
        groupId,
      ]);
      created = true;
    }

    const expiresAt = new Date(Date.now() + input.sessionTtlMs);
    const sess = await client.query<{ id: string }>(
      `INSERT INTO user_sessions (user_id, workspace_id, device_name, ip_address, expires_at)
       VALUES ($1, $2, $3, $4::inet, $5)
       RETURNING id`,
      [userId, workspace.id, input.deviceName, input.ipAddress, expiresAt],
    );

    await client.query('COMMIT');
    return {
      userId,
      email,
      workspaceId: workspace.id,
      sessionId: sess.rows[0]!.id,
      expiresAt,
      created,
    };
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}

function defaultPageEditMode(settings: unknown): 'read' | 'edit' | undefined {
  const mode = (settings as { defaultPageEditMode?: unknown } | null)?.defaultPageEditMode;
  return mode === 'read' || mode === 'edit' ? mode : undefined;
}
