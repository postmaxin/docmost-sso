// Docmost access token and auth cookie construction.
//
// Docmost (v0.96.0) signs `{sub, email, workspaceId, type: "access", sessionId}`
// with HS256 / APP_SECRET, issuer "Docmost", and `exp = iat + JWT_TOKEN_EXPIRES_IN`.
// Its JWT strategy reads the token from the `authToken` cookie and checks the
// signature, expiry, workspace, that the user is not disabled and, because we
// always include `sessionId`, that the user_sessions row is active.

import { SignJWT } from 'jose';

export const AUTH_COOKIE = 'authToken';
export const DOCMOST_JWT_ISSUER = 'Docmost';

export interface AccessTokenInput {
  userId: string;
  email: string;
  workspaceId: string;
  sessionId: string;
  /** Issue time; injectable for tests. */
  now?: Date;
}

export async function signAccessToken(
  input: AccessTokenInput,
  appSecret: string,
  ttlMs: number,
): Promise<string> {
  const iat = Math.floor((input.now ?? new Date()).getTime() / 1000);
  // jsonwebtoken computes exp as iat + floor(ms(expiresIn) / 1000).
  const exp = iat + Math.floor(ttlMs / 1000);
  return new SignJWT({
    sub: input.userId,
    email: input.email,
    workspaceId: input.workspaceId,
    type: 'access',
    sessionId: input.sessionId,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setIssuer(DOCMOST_JWT_ISSUER)
    .sign(new TextEncoder().encode(appSecret));
}

export interface CookieAttributes {
  httpOnly: true;
  sameSite: 'lax';
  path: '/';
  secure: boolean;
  expires: Date;
}

/** The exact attributes Docmost's setAuthCookie uses. */
export function authCookieAttributes(appUrl: URL, expiresAt: Date): CookieAttributes {
  return {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    // Docmost: secure iff APP_URL is https.
    secure: appUrl.protocol === 'https:',
    expires: expiresAt,
  };
}
