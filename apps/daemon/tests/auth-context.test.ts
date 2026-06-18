// Phase 2 auth gate logic — deterministic unit tests for the per-user /api gate
// that replaces the shared OD_API_TOKEN. (Live HTTP integration is exercised
// separately; this pins the authorization decisions.)

import { describe, expect, it, vi } from 'vitest';
import { createApiAuthGate, requestToHeaders, resolveRequestAuth } from '../src/auth-context.js';

type FakeAuth = { api: { getSession: (args: { headers: Headers }) => Promise<unknown> } };
const authReturning = (value: unknown): FakeAuth => ({ api: { getSession: vi.fn(async () => value) } });

function fakeReq(over: { path?: string; remote?: string; headers?: Record<string, string> } = {}) {
  return {
    path: over.path ?? '/api/projects',
    headers: over.headers ?? {},
    socket: { remoteAddress: over.remote ?? '203.0.113.9' },
    auth: undefined as unknown,
  } as any;
}
function fakeRes() {
  const res: any = { statusCode: 0, body: undefined };
  res.status = (c: number) => { res.statusCode = c; return res; };
  res.json = (b: unknown) => { res.body = b; return res; };
  return res;
}
const loopback = (a: string | undefined) => a === '127.0.0.1' || a === '::1';
const flush = () => new Promise((r) => setTimeout(r, 0));

describe('createApiAuthGate', () => {
  it('is a pass-through when auth is disabled', async () => {
    const next = vi.fn();
    createApiAuthGate({ auth: null, isLoopbackPeer: loopback })(fakeReq(), fakeRes(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('allows loopback peers without a session', () => {
    const next = vi.fn();
    createApiAuthGate({ auth: authReturning(null) as any, isLoopbackPeer: loopback })(
      fakeReq({ remote: '127.0.0.1' }), fakeRes(), next,
    );
    expect(next).toHaveBeenCalledOnce();
  });

  it('opens probe and /api/auth paths', () => {
    const gate = createApiAuthGate({ auth: authReturning(null) as any, isLoopbackPeer: loopback });
    for (const path of ['/api/health', '/api/auth/get-session', '/api/auth/sign-in/email']) {
      const next = vi.fn();
      gate(fakeReq({ path }), fakeRes(), next);
      expect(next, path).toHaveBeenCalledOnce();
    }
  });

  it('401s a non-loopback request with no session', async () => {
    const next = vi.fn();
    const res = fakeRes();
    createApiAuthGate({ auth: authReturning(null) as any, isLoopbackPeer: loopback })(fakeReq(), res, next);
    await flush();
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect((res.body as any).error.code).toBe('AUTH_REQUIRED');
  });

  it('allows a non-loopback request with a valid session and attaches req.auth', async () => {
    const next = vi.fn();
    const req = fakeReq();
    createApiAuthGate({
      auth: authReturning({ user: { id: 'u1' }, session: { activeOrganizationId: 'org1' } }) as any,
      isLoopbackPeer: loopback,
    })(req, fakeRes(), next);
    await flush();
    expect(next).toHaveBeenCalledOnce();
    expect(req.auth).toEqual({ userId: 'u1', activeOrganizationId: 'org1' });
  });

  it('accepts the deprecated legacy API token as a bearer fallback', async () => {
    const next = vi.fn();
    createApiAuthGate({
      auth: authReturning(null) as any,
      isLoopbackPeer: loopback,
      legacyApiToken: 'legacy-tok',
    })(fakeReq({ headers: { authorization: 'Bearer legacy-tok' } }), fakeRes(), next);
    await flush();
    expect(next).toHaveBeenCalledOnce();
  });

  it('legacy-token-only mode (no per-user auth) 401s without the token', () => {
    const next = vi.fn();
    const res = fakeRes();
    createApiAuthGate({ auth: null, isLoopbackPeer: loopback, legacyApiToken: 'tok' })(fakeReq(), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(401);
    expect((res.body as any).error.code).toBe('API_TOKEN_REQUIRED');
  });

  it('fails CLOSED with 503 when auth is configured but the backend is down', () => {
    const next = vi.fn();
    const res = fakeRes();
    createApiAuthGate({ auth: null, authConfigured: true, isLoopbackPeer: loopback })(fakeReq(), res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(503);
    expect((res.body as any).error.code).toBe('AUTH_UNAVAILABLE');
  });

  it('configured-but-down still allows loopback + probes (recovery/health)', () => {
    const gate = createApiAuthGate({ auth: null, authConfigured: true, isLoopbackPeer: loopback });
    const n1 = vi.fn(); gate(fakeReq({ remote: '127.0.0.1' }), fakeRes(), n1); expect(n1).toHaveBeenCalledOnce();
    const n2 = vi.fn(); gate(fakeReq({ path: '/api/health' }), fakeRes(), n2); expect(n2).toHaveBeenCalledOnce();
  });

  it('respects the isExempt hook (e.g. preview-asset scopes)', () => {
    const next = vi.fn();
    createApiAuthGate({
      auth: authReturning(null) as any,
      isLoopbackPeer: loopback,
      isExempt: (req) => req.path === '/api/projects/p1/preview/style.css',
    })(fakeReq({ path: '/api/projects/p1/preview/style.css' }), fakeRes(), next);
    expect(next).toHaveBeenCalledOnce();
  });
});

describe('resolveRequestAuth', () => {
  it('returns null without a user', async () => {
    expect(await resolveRequestAuth(new Headers(), authReturning(null) as any)).toBeNull();
  });
  it('maps the session to a RequestAuth', async () => {
    const auth = authReturning({ user: { id: 'u9' }, session: { activeOrganizationId: null } }) as any;
    expect(await resolveRequestAuth(new Headers(), auth)).toEqual({ userId: 'u9', activeOrganizationId: null });
  });
});

describe('requestToHeaders', () => {
  it('copies string and array headers', () => {
    const h = requestToHeaders({ headers: { origin: 'http://x', 'x-multi': ['a', 'b'] } } as any);
    expect(h.get('origin')).toBe('http://x');
    expect(h.get('x-multi')).toBe('a, b');
  });
});
