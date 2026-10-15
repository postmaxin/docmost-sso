# docmost-sso

A small OpenID Connect sign-in service for self-hosted
[Docmost](https://github.com/docmost/docmost) community edition. People sign
in with your identity provider (tested with Google Workspace; any OIDC
provider such as Authentik or Dex should work, as long as it sends
`email_verified: true`) and land in Docmost with a
normal Docmost session. They never get a Docmost password.

It is an independent program: it contains no Docmost code and talks to
Docmost only through its PostgreSQL database and its `authToken` cookie.

> **Status:** tested against Docmost **v0.96.0** only. The shim refuses to
> serve sign-ins against any other database schema version (see
> [Upgrading Docmost](#upgrading-docmost)).

## How it works

```
browser ─> /sso/login ─> /sso/start ─> IdP ─> /sso/callback ─> 302 /home
                                                  │
                                                  └─ SQL: find-or-create user,
                                                     insert user_sessions row
```

1. `GET /sso/login` shows a "Sign in with …" button. It never redirects on
   its own, so Docmost's logout (which goes to `/login`) does not sign the
   user straight back in. `?auto=1` skips the page. `?redirect=/path` (the
   parameter Docmost's own client uses; `returnTo` also works) is carried
   through the flow.
2. `GET /sso/start` starts an authorization-code flow with PKCE. `state`,
   `nonce`, the PKCE verifier and the return path travel in a 10-minute,
   encrypted, `HttpOnly` cookie scoped to `/sso/`.
3. `GET /sso/callback` exchanges the code and validates the ID token
   (issuer, audience, expiry, nonce, state, PKCE), then admits the user only
   if:
   - `email_verified` is `true`;
   - the email's domain is in `SSO_ALLOWED_DOMAINS` (exact match, no
     subdomains), unless that is `*`;
   - when the issuer is Google, the `hd` (hosted domain) claim is present
     and in `SSO_ALLOWED_DOMAINS` (any issuer: an `hd` claim, if sent, must
     be allowed).
4. In one transaction it finds the user by lower-cased email in the
   workspace, or creates them the way Docmost's sign-up does (role = the
   workspace's default role, membership of the default "Everyone" group, the
   workspace's default page-edit mode, an unusable random bcrypt password).
   Deactivated or deleted users are refused. It then inserts a real
   `user_sessions` row, signs Docmost's access JWT (HS256 with `APP_SECRET`,
   including the `sessionId`), sets the `authToken` cookie with Docmost's
   exact attributes and redirects to `/home` or the validated return path.
   Because the session is real, Docmost's logout, session list and
   revocation all work.
5. `GET /sso/healthz` returns 200 when the database is reachable and its
   newest Docmost migration is one the shim supports; 503 otherwise.

Each sign-in outcome is logged as one JSON line (email, user id, created or
existing, refusal reason, client IP). Tokens, codes and secrets are never
logged.

## Running it

Images are published to GitHub Container Registry for `linux/amd64` and
`linux/arm64`, tagged by version (`0.2.0`, `0.2`, `latest`):

```yaml
# Next to Docmost in its docker compose file.
services:
  docmost-sso:
    image: ghcr.io/postmaxin/docmost-sso:0.2
    environment:
      APP_URL: https://docs.example.com     # same as Docmost's
      APP_SECRET: ${APP_SECRET}             # same as Docmost's
      DATABASE_URL: postgresql://docmost:${DB_PASSWORD}@db:5432/docmost
      SESSION_TTL: 7d                       # = Docmost's JWT_TOKEN_EXPIRES_IN
      OIDC_ISSUER: https://auth.example.com/application/o/docmost/
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      SSO_ALLOWED_DOMAINS: example.com
      SSO_PROVIDER_NAME: Authentik
    restart: unless-stopped
```

For production, pin the digest too (`:0.2.0@sha256:…`). Then route
`/sso/*` to it as described below. The image runs as the unprivileged
`node` user and has a built-in health check.

## Deployment

Route `/sso/*` on Docmost's public origin to this service, and redirect
`/login` to `/sso/login` (keeping the query string). The shim must share
Docmost's origin because the cookie it sets is Docmost's session cookie.
Register `<APP_URL>/sso/callback` as the redirect URI at your IdP.

Consider blocking Docmost's password endpoints (`/api/auth/login`,
`/api/auth/forgot-password`, `/api/auth/password-reset`, `/api/auth/setup`)
at the proxy for everyone except a break-glass network.

### Configuration

| Variable | Required | Meaning |
| --- | --- | --- |
| `APP_URL` | yes | Docmost's public URL (same value as Docmost's). Only the origin is used. |
| `APP_SECRET` | yes | Docmost's `APP_SECRET` (signs the session JWT). |
| `DATABASE_URL` | yes | Docmost's PostgreSQL database. See TLS below. |
| `SESSION_TTL` | yes | Must equal Docmost's `JWT_TOKEN_EXPIRES_IN`, e.g. `7d`. A unit is required (`ms s m h d w y`). |
| `OIDC_ISSUER` | yes | e.g. `https://accounts.google.com`. |
| `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` | yes | The OIDC client. |
| `SSO_ALLOWED_DOMAINS` | yes | Comma-separated email domains, e.g. `example.com`. `*` on its own allows every domain (and skips the `hd` check); use it only when the IdP already decides who may sign in, e.g. an application bound to a group. |
| `PORT` | no | Listen port, default `8080`. `HOST` defaults to `0.0.0.0`. |
| `TRUST_PROXY` | no | Proxies whose `X-Forwarded-For` is trusted: comma-separated addresses, CIDRs or the presets `loopback`, `linklocal`, `uniquelocal`; or `true`/`false`. Default `loopback,linklocal,uniquelocal`. Used only for the session's IP address. |
| `SSO_PROVIDER_NAME` | no | Button label, default `Google`. |
| `SSO_DEFAULT_RETURN_TO` | no | Where people land after signing in when they weren't heading to a specific page. A same-origin path, default `/home`. |
| `OIDC_ALLOW_INSECURE_ISSUER` | no | `true` allows an `http://` issuer. Tests only. |

Redirect URIs and cookies are always derived from `APP_URL`, never from
`Host` or `X-Forwarded-*` headers.

### Database TLS

`sslmode` follows libpq semantics:

- `sslmode=disable` (or absent): no TLS.
- `sslmode=require`: encrypted, certificate **not** verified.
- `sslmode=verify-ca&sslrootcert=<file>`: chain verified, host name not.
- `sslmode=verify-full&sslrootcert=<file>`: chain and host name verified.

Mount the CA file into the container (read-only) and point `sslrootcert`
at it. For Amazon RDS, use the
[global bundle](https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem):
`verify-full` against the RDS endpoint name, `verify-ca` through a CNAME
(whose name is not on the RDS certificate).

### Making someone an admin

The shim creates users with the workspace's default role (normally
`member`). Promote in Docmost's UI, or in SQL:

```sql
UPDATE users SET role = 'admin' WHERE email = 'someone@example.com';
```

## Upgrading Docmost

The shim writes Docmost's tables directly, so a Docmost upgrade is a
deliberate step:

1. Bump the Docmost image in `test/integration/docker-compose.yml`.
2. Run the integration test (below). Read the new migrations for changes to
   `users`, `groups`, `group_users`, `user_sessions` and `workspaces`, and to
   Docmost's sign-up, session and JWT code.
3. Add the new newest migration name to `SUPPORTED_MIGRATIONS` in
   `src/docmost.ts`.

Until then `/sso/healthz` returns 503 and sign-in shows "temporarily
unavailable"; existing Docmost sessions keep working.

## Development

```sh
npm ci
npm test                  # build + unit tests
npm run test:integration  # Docker: Docmost + Postgres + Redis + shim + mock IdP
```

The integration test boots the pinned Docmost image, creates the workspace
through Docmost's setup API, and signs in through the shim against
[mock-oauth2-server](https://github.com/navikt/mock-oauth2-server): an
existing admin, a new user (created as a member of the default group), a
refused domain, an unverified email, a replayed callback, logout revoking the
session, and a deactivated user. It removes its containers and volumes when
done.

## Releasing

Push a tag `vX.Y.Z` matching `package.json`'s version. CI runs the unit and
integration tests, then publishes `ghcr.io/postmaxin/docmost-sso:X.Y.Z`,
`:X.Y` and `:latest`.

## Licence

[MIT](LICENSE). docmost-sso is not affiliated with Docmost and contains no
Docmost code.
