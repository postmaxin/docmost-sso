// Fetch for IdP requests (discovery, token) that retries a connection that
// never opened. Behind a tunnel or a lossy uplink, a few lost SYNs can push one
// connect past undici's 10 s timeout. That used to fail the whole sign-in after
// the user had already authenticated at the IdP.

/**
 * `cause.code`s that mean the request never left this process: the connection
 * was not established, or the name did not resolve. Retrying them cannot
 * present an authorization code twice. A reset or timeout after the connection
 * opened is deliberately absent, because the IdP may already have redeemed the code.
 */
const NOT_SENT = new Set([
  'UND_ERR_CONNECT_TIMEOUT',
  'ECONNREFUSED',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EAI_AGAIN',
]);

/** The `cause.code` of a fetch failure, if it has one. */
export function causeCode(err: unknown): string | undefined {
  const cause = (err as { cause?: unknown } | null)?.cause;
  const code = (cause as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : undefined;
}

/** True when `err` is a fetch failure that happened before the request was sent. */
export function isNotSent(err: unknown): boolean {
  if (!(err instanceof TypeError)) return false;
  const code = causeCode(err);
  return code !== undefined && NOT_SENT.has(code);
}

/**
 * True for any network-level fetch failure (fetch rejects with a TypeError
 * whose cause carries a code), sent or not: the IdP could not be reached or
 * did not answer, as opposed to answering with an error or a bad token.
 */
export function isNetworkFailure(err: unknown): boolean {
  return err instanceof TypeError && causeCode(err) !== undefined;
}

/** Generic over the options type: openid-client passes its own CustomFetchOptions. */
type Fetch<O> = (url: string, options: O) => Promise<Response>;

/**
 * `attempts` tries in all, retrying only failures for which isNotSent holds.
 * The caller's body must be reusable; openid-client sends strings,
 * URLSearchParams or byte arrays.
 */
export function retryingFetch<O>(
  attempts = 3,
  inner: Fetch<O> = (url, options) => fetch(url, options as RequestInit),
): Fetch<O> {
  return async (url, options) => {
    for (let attempt = 1; ; attempt++) {
      try {
        return await inner(url, options);
      } catch (err) {
        if (attempt >= attempts || !isNotSent(err)) throw err;
      }
    }
  };
}
