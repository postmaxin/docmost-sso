// OIDC relying-party logic (authorization code flow + PKCE) on openid-client.

import * as client from 'openid-client';
import { allowsAnyDomain, GOOGLE_ISSUER, type IdClaims } from './claims.js';
import type { FlowState } from './flow-cookie.js';

export interface OidcSettings {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  allowInsecure: boolean;
  /** Passed to Google as the `hd` hint when there is exactly one allowed domain. */
  allowedDomains: readonly string[];
}

export class Oidc {
  private config: Promise<client.Configuration> | undefined;

  constructor(private readonly s: OidcSettings) {}

  /** Discovery is lazy and retried on failure, so an IdP blip doesn't crash the shim. */
  private getConfig(): Promise<client.Configuration> {
    if (!this.config) {
      this.config = client
        .discovery(
          new URL(this.s.issuer),
          this.s.clientId,
          this.s.clientSecret,
          undefined,
          this.s.allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined,
        )
        .catch((err: unknown) => {
          this.config = undefined;
          throw err;
        });
    }
    return this.config;
  }

  private isGoogle(): boolean {
    return this.s.issuer.replace(/\/$/, '') === GOOGLE_ISSUER;
  }

  async begin(returnTo: string): Promise<{ url: URL; flow: FlowState }> {
    const config = await this.getConfig();
    const codeVerifier = client.randomPKCECodeVerifier();
    const flow: FlowState = {
      state: client.randomState(),
      nonce: client.randomNonce(),
      codeVerifier,
      returnTo,
    };
    const params: Record<string, string> = {
      redirect_uri: this.s.redirectUri,
      scope: 'openid email profile',
      response_type: 'code',
      code_challenge: await client.calculatePKCECodeChallenge(codeVerifier),
      code_challenge_method: 'S256',
      state: flow.state,
      nonce: flow.nonce,
    };
    if (this.isGoogle()) {
      // UX hints only; the hd claim is enforced on the callback.
      params.prompt = 'select_account';
      if (this.s.allowedDomains.length === 1 && !allowsAnyDomain(this.s.allowedDomains)) {
        params.hd = this.s.allowedDomains[0]!;
      }
    }
    return { url: client.buildAuthorizationUrl(config, params), flow };
  }

  /**
   * Exchange the code and validate the ID token (issuer, audience, expiry,
   * nonce; state and PKCE are checked too). Returns the ID token claims.
   */
  async complete(callbackUrl: URL, flow: FlowState): Promise<IdClaims> {
    const config = await this.getConfig();
    const tokens = await client.authorizationCodeGrant(config, callbackUrl, {
      pkceCodeVerifier: flow.codeVerifier,
      expectedState: flow.state,
      expectedNonce: flow.nonce,
      idTokenExpected: true,
    });
    const claims = tokens.claims();
    if (!claims) throw new Error('no ID token claims');
    return claims as unknown as IdClaims;
  }
}
