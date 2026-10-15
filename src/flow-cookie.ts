// The short-lived cookie that carries OIDC transaction state (state, nonce,
// PKCE verifier, return path) from /sso/start to /sso/callback. It is
// encrypted and authenticated (JWE, dir + A256GCM) with a key derived from
// APP_SECRET via HKDF, so it is bound to this deployment and opaque to the
// browser.

import { hkdfSync } from 'node:crypto';
import { EncryptJWT, jwtDecrypt } from 'jose';

export const FLOW_COOKIE = 'docmost_sso_flow';
export const FLOW_TTL_SECONDS = 600;
const PURPOSE = 'docmost-sso flow cookie v1';

export interface FlowState {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
}

export function deriveFlowKey(appSecret: string): Uint8Array {
  return new Uint8Array(hkdfSync('sha256', appSecret, 'docmost-sso', PURPOSE, 32));
}

export async function sealFlow(flow: FlowState, key: Uint8Array): Promise<string> {
  return new EncryptJWT({ ...flow })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime(`${FLOW_TTL_SECONDS}s`)
    .setAudience(PURPOSE)
    .encrypt(key);
}

/** Returns null for anything missing, tampered with, expired or malformed. */
export async function openFlow(token: string | undefined, key: Uint8Array): Promise<FlowState | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtDecrypt(token, key, {
      audience: PURPOSE,
      keyManagementAlgorithms: ['dir'],
      contentEncryptionAlgorithms: ['A256GCM'],
    });
    const { state, nonce, codeVerifier, returnTo } = payload;
    if (
      typeof state !== 'string' ||
      typeof nonce !== 'string' ||
      typeof codeVerifier !== 'string' ||
      typeof returnTo !== 'string'
    ) {
      return null;
    }
    return { state, nonce, codeVerifier, returnTo };
  } catch {
    return null;
  }
}
