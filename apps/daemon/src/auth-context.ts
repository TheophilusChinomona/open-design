import type { Request, RequestHandler } from 'express';
import type { OpenDesignAuth } from './routes/auth.js';

/** The authenticated principal attached to a gated request. */
export interface RequestAuth {
  userId: string;
  activeOrganizationId: string | null;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      auth?: RequestAuth;
    }
  }
}

/** Endpoints that stay open for monitoring probes (no auth). */
const OPEN_PROBE_PATHS = new Set(['/health', '/api/health', '/ready', '/api/ready', '/version', '/api/version']);

/** Convert Express request headers into a WHATWG Headers (for better-auth). */
export function requestToHeaders(req: Pick<Request, 'headers'>): Headers {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, item);
    } else if (value != null) {
      headers.set(key, String(value));
    }
  }
  return headers;
}

/**
 * Resolve the authenticated user for a request from its better-auth session
 * (cookie) or bearer token, or null when unauthenticated.
 */
export async function resolveRequestAuth(headers: Headers, auth: OpenDesignAuth): Promise<RequestAuth | null> {
  const result = await auth.api.getSession({ headers });
  const user = (result as { user?: { id?: string } } | null)?.user;
  if (!user?.id) return null;
  const session = (result as { session?: { activeOrganizationId?: string | null } } | null)?.session;
  return { userId: user.id, activeOrganizationId: session?.activeOrganizationId ?? null };
}

export interface ApiAuthGateOptions {
  /** The better-auth instance; null when per-user auth is disabled (no DB). */
  auth: OpenDesignAuth | null;
  /** True when the request's socket peer is loopback (local desktop/CLI/dev). */
  isLoopbackPeer: (address: string | undefined) => boolean;
  /** Deprecated shared token still accepted as a bearer fallback (OD_API_TOKEN). */
  legacyApiToken?: string;
  /** Extra exemption hook (e.g. server-minted GET preview-asset scopes for iframes). */
  isExempt?: (req: Request) => boolean;
}

function bearerToken(headers: Headers): string | null {
  const raw = headers.get('authorization') ?? '';
  const match = /^Bearer\s+(\S+)\s*$/i.exec(raw);
  return match ? match[1]! : null;
}

/**
 * Per-user gate for `/api/*`. Replaces the shared-secret OD_API_TOKEN model:
 * every non-loopback API request must carry a valid better-auth session or
 * bearer token. Loopback peers (the local desktop/CLI/dev daemon) stay trusted;
 * probes and `/api/auth/*` stay open. When auth is disabled the gate is a
 * pass-through so a no-DB instance behaves exactly as before.
 */
export function createApiAuthGate(options: ApiAuthGateOptions): RequestHandler {
  const { auth, isLoopbackPeer, legacyApiToken, isExempt } = options;
  // Nothing to enforce when there are neither accounts nor a shared token: a
  // plain local/no-auth instance behaves exactly as before.
  const enforcing = Boolean(auth) || Boolean(legacyApiToken);
  return (req, res, next) => {
    if (!enforcing) return next();

    const path = req.path.startsWith('/api/') ? req.path : `/api${req.path}`;
    if (OPEN_PROBE_PATHS.has(req.path) || OPEN_PROBE_PATHS.has(path)) return next();
    if (path.startsWith('/api/auth/') || path === '/api/auth') return next();
    if (isExempt?.(req)) return next();

    if (isLoopbackPeer(req.socket?.remoteAddress)) return next();

    const headers = requestToHeaders(req);
    if (legacyApiToken && bearerToken(headers) === legacyApiToken) return next();

    if (!auth) {
      // Legacy-token-only deployment and the token was absent/wrong.
      res.status(401).json({
        error: { code: 'API_TOKEN_REQUIRED', message: 'Authorization: Bearer <OD_API_TOKEN> required' },
      });
      return;
    }

    void resolveRequestAuth(headers, auth)
      .then((principal) => {
        if (!principal) {
          res.status(401).json({
            error: { code: 'AUTH_REQUIRED', message: 'Sign in to access this Open Design instance.' },
          });
          return;
        }
        req.auth = principal;
        next();
      })
      .catch((err) => {
        res.status(500).json({ error: { code: 'AUTH_ERROR', message: String(err?.message ?? err) } });
      });
  };
}
