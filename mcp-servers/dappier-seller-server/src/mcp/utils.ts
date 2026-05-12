import crypto from 'crypto'
import jwksClient from 'jwks-rsa'
import logger from '../logger'
import type { JwtHeader, SigningKeyCallback } from 'jsonwebtoken'

/**
 * Normalizes a JWT issuer claim into a canonical form.
 *
 * - Trims whitespace
 * - Ensures exactly one trailing `/` (Auth0 tokens include a trailing slash)
 */
export function normalizeIssuer(iss: unknown): string | null {
  if (typeof iss !== 'string') return null
  const trimmed = iss.trim()
  if (!trimmed) return null
  return trimmed.endsWith('/') ? trimmed : `${trimmed}/`
}

/**
 * Computes the JWKS URL for an issuer (e.g. `https://tenant.us.auth0.com/`).
 *
 * IMPORTANT: `issuer` must already be normalized and include a trailing slash.
 */
export function jwksUriFromIssuer(issuer: string): string {
  return `${issuer}.well-known/jwks.json`
}

const issuerClientCache = new Map<string, ReturnType<typeof jwksClient>>()

/**
 * Gets a cached `jwks-rsa` client for a given issuer.
 */
export function getClientForIssuer(
  issuer: string
): ReturnType<typeof jwksClient> {
  const existing = issuerClientCache.get(issuer)
  if (existing) return existing

  const client = jwksClient({
    jwksUri: jwksUriFromIssuer(issuer),
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 10
  })
  issuerClientCache.set(issuer, client)
  return client
}

/**
 * Returns a short, non-reversible fingerprint of a PEM public key.
 */
export function publicKeyFingerprint(publicKeyPem: string): string {
  return crypto
    .createHash('sha256')
    .update(publicKeyPem)
    .digest('hex')
    .slice(0, 12)
}

/**
 * Fingerprints RSA JWK key material via SHA-256 over `n.e` (modulus + exponent).
 */
export function jwkFingerprintNThenE(jwk: {
  n?: string
  e?: string
}): string | null {
  if (!jwk?.n || !jwk?.e) return null
  return crypto
    .createHash('sha256')
    .update(`${jwk.n}.${jwk.e}`)
    .digest('hex')
    .slice(0, 12)
}

/**
 * Derives a JWK from a PEM public key (via Node `crypto`) and fingerprints it.
 */
export function jwkFingerprintFromPem(publicKeyPem: string): string | null {
  try {
    const jwk = crypto
      .createPublicKey(publicKeyPem)
      .export({ format: 'jwk' }) as unknown as { n?: string; e?: string }
    return jwkFingerprintNThenE(jwk)
  } catch {
    return null
  }
}

/**
 * Attempts to extract an RSA JWK `{ n, e }` from the jwks-rsa signing key object.
 */
export function extractJwkFromSigningKey(
  key: unknown
): { n?: string; e?: string } | null {
  if (!key || typeof key !== 'object') return null
  const k = key as Record<string, unknown>

  const direct = k.key
  if (direct && typeof direct === 'object') {
    const jwk = direct as { n?: string; e?: string }
    if (typeof jwk.n === 'string' && typeof jwk.e === 'string') return jwk
  }

  const maybeRsa = k.rsaPublicKey
  if (maybeRsa && typeof maybeRsa === 'object') {
    const jwk = maybeRsa as { n?: string; e?: string }
    if (typeof jwk.n === 'string' && typeof jwk.e === 'string') return jwk
  }

  const maybePub = k.publicKey
  if (maybePub && typeof maybePub === 'object') {
    const jwk = maybePub as { n?: string; e?: string }
    if (typeof jwk.n === 'string' && typeof jwk.e === 'string') return jwk
  }

  return null
}

/**
 * Extracts a JWT substring from a larger string.
 */
export function extractJwt(tokenLike: string): string | null {
  if (typeof tokenLike !== 'string') return null
  const match = tokenLike.match(
    /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/
  )
  return match?.[0] ?? null
}

/**
 * Produces a safe-to-log fingerprint for a token-like string.
 */
export function tokenDebugFingerprint(tokenLike: string): {
  sha256_12: string
  parts: number[]
  length: number
} {
  const token = tokenLike ?? ''
  const parts = token.split('.').map((p) => p.length)
  const sha256_12 = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex')
    .slice(0, 12)
  return { sha256_12, parts, length: token.length }
}

/**
 * Produces per-segment fingerprints for a JWT (header/payload/signature).
 */
export function tokenSegmentFingerprints(tokenLike: string): {
  header_sha256_12?: string
  payload_sha256_12?: string
  signature_sha256_12?: string
} {
  if (typeof tokenLike !== 'string') return {}
  const segs = tokenLike.split('.')
  if (segs.length !== 3) return {}
  const [h, p, s] = segs
  const fp = (x: string) =>
    crypto.createHash('sha256').update(x).digest('hex').slice(0, 12)
  return {
    header_sha256_12: fp(h),
    payload_sha256_12: fp(p),
    signature_sha256_12: fp(s)
  }
}

/**
 * Normalizes a value that is supposed to contain an access token.
 */
export function normalizeTokenLike(input: string): string {
  let s = typeof input === 'string' ? input.trim() : ''

  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1).trim()
  }

  if (s.startsWith('{') && s.includes('accessToken')) {
    try {
      const parsed = JSON.parse(s) as unknown
      if (parsed && typeof parsed === 'object') {
        const maybe = (parsed as { accessToken?: unknown }).accessToken
        if (typeof maybe === 'string' && maybe.length > 0) s = maybe.trim()
      }
    } catch {
      // ignore
    }
  }

  return s
}

export type SigningKeyFingerprints = {
  pem_sha256_12: string
  jwk_ne_sha256_12: string | null
}

/**
 * Retrieves a signing key using a JWKS endpoint derived from the token issuer.
 *
 * Returns the signing key PEM via callback and updates `lastSigningKeyFingerprints`.
 */
export function getKeyForIssuer(params: {
  issuer: string
  header: JwtHeader
  callback: SigningKeyCallback
  setLastSigningKeyFingerprints: (fp: SigningKeyFingerprints | null) => void
}) {
  const { issuer, header, callback, setLastSigningKeyFingerprints } = params

  const kidRaw = header?.kid
  const kid = typeof kidRaw === 'string' ? kidRaw.trim() : ''

  if (!kid) {
    const err = new Error(
      'JWT header missing or invalid "kid" (expected non-empty string)'
    )
    logger.warn(
      {
        jwks: { uri: jwksUriFromIssuer(issuer) },
        tokenHeader: { kid: kidRaw, alg: header?.alg, typ: header?.typ },
        err: { name: err.name, message: err.message }
      },
      'Auth0 JWKS: cannot retrieve signing key because token header kid is missing/invalid'
    )
    callback(err)
    return
  }

  const issuerClient = getClientForIssuer(issuer)

  logger.debug(
    {
      jwks: { uri: jwksUriFromIssuer(issuer), cache: true, rateLimit: true },
      tokenHeader: { kid, alg: header.alg, typ: header.typ },
      issuer
    },
    'Auth0 JWKS: retrieving signing key (issuer-derived)'
  )

  issuerClient.getSigningKey(kid, (err, key) => {
    if (err) {
      logger.warn(
        {
          jwks: { uri: jwksUriFromIssuer(issuer) },
          tokenHeader: { kid, alg: header.alg, typ: header.typ },
          issuer,
          err: { name: err.name, message: err.message }
        },
        'Auth0 JWKS: failed to retrieve signing key (issuer-derived)'
      )
      callback(err)
      return
    }

    const signingKey = key?.getPublicKey()
    const maybeJwk = extractJwkFromSigningKey(key as unknown)
    const jwkNeSha =
      (maybeJwk ? jwkFingerprintNThenE(maybeJwk) : null) ??
      (signingKey ? jwkFingerprintFromPem(signingKey) : null)

    if (signingKey) {
      setLastSigningKeyFingerprints({
        pem_sha256_12: publicKeyFingerprint(signingKey),
        jwk_ne_sha256_12: jwkNeSha
      })

      logger.debug(
        {
          jwks: { uri: jwksUriFromIssuer(issuer) },
          tokenHeader: { kid, alg: header.alg, typ: header.typ },
          issuer,
          signingKey: {
            pem_sha256_12: publicKeyFingerprint(signingKey),
            jwk_ne_sha256_12: jwkNeSha
          }
        },
        'Auth0 JWKS: retrieved signing key (issuer-derived)'
      )
    }

    callback(null, signingKey)
  })
}
