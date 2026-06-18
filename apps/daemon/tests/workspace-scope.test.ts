// Phase 5 — workspace (organization) data isolation, DB-only ownership model.
// Pure logic: resolve a request's scope, filter/stamp owned records.

import { describe, expect, it, vi } from 'vitest';
import {
  canAccessRecord,
  createProjectWorkspaceGate,
  resolveWorkspaceScope,
  scopeRecords,
  stampWorkspace,
} from '../src/workspace-scope.js';

describe('resolveWorkspaceScope', () => {
  it('is unscoped for a loopback/local request (no req.auth)', () => {
    expect(resolveWorkspaceScope({ auth: undefined } as any)).toEqual({ workspaceId: null, scoped: false });
  });
  it('scopes an authenticated request to its active workspace', () => {
    expect(resolveWorkspaceScope({ auth: { userId: 'u1', activeOrganizationId: 'w1' } } as any))
      .toEqual({ workspaceId: 'w1', scoped: true });
  });
  it('is scoped-but-empty when the user has no active workspace yet', () => {
    expect(resolveWorkspaceScope({ auth: { userId: 'u1', activeOrganizationId: null } } as any))
      .toEqual({ workspaceId: null, scoped: true });
  });
});

describe('canAccessRecord', () => {
  const local = { workspaceId: null, scoped: false } as const;
  const w1 = { workspaceId: 'w1', scoped: true } as const;
  it('local sees everything', () => {
    expect(canAccessRecord(local, 'w1')).toBe(true);
    expect(canAccessRecord(local, null)).toBe(true);
  });
  it('scoped sees only its own workspace', () => {
    expect(canAccessRecord(w1, 'w1')).toBe(true);
    expect(canAccessRecord(w1, 'w2')).toBe(false);
    expect(canAccessRecord(w1, null)).toBe(false);
  });
  it('scoped-but-no-workspace sees nothing', () => {
    expect(canAccessRecord({ workspaceId: null, scoped: true }, 'w1')).toBe(false);
  });
});

describe('scopeRecords', () => {
  const records = [{ id: 'a', workspaceId: 'w1' }, { id: 'b', workspaceId: 'w2' }, { id: 'c' }];
  it('returns all for local', () => {
    expect(scopeRecords({ workspaceId: null, scoped: false }, records).map((r) => r.id)).toEqual(['a', 'b', 'c']);
  });
  it('returns only the workspace records for a scoped request', () => {
    expect(scopeRecords({ workspaceId: 'w1', scoped: true }, records).map((r) => r.id)).toEqual(['a']);
  });
});

describe('stampWorkspace', () => {
  type Rec = { id: string; workspaceId?: string | null };
  it('stamps the active workspace on create when scoped', () => {
    const rec: Rec = { id: 'x' };
    expect(stampWorkspace({ workspaceId: 'w1', scoped: true }, rec)).toEqual({ id: 'x', workspaceId: 'w1' });
  });
  it('leaves the record unchanged when unscoped (local)', () => {
    const rec: Rec = { id: 'x' };
    expect(stampWorkspace({ workspaceId: null, scoped: false }, rec)).toBe(rec);
  });
});

describe('createProjectWorkspaceGate', () => {
  // owners: project 'p-w1' belongs to w1, 'p-w2' to w2, 'p-legacy' is unowned.
  const owners: Record<string, string | null> = { 'p-w1': 'w1', 'p-w2': 'w2', 'p-legacy': null };
  const lookup = (id: string) =>
    id in owners ? { exists: true, workspaceId: owners[id]! } : { exists: false, workspaceId: null };
  const gate = createProjectWorkspaceGate(lookup);

  function req(id: string, auth?: { userId: string; activeOrganizationId: string | null }) {
    return { params: { id }, auth } as any;
  }
  function res() {
    const r: any = { statusCode: 0, body: undefined };
    r.status = (c: number) => { r.statusCode = c; return r; };
    r.json = (b: unknown) => { r.body = b; return r; };
    return r;
  }
  const w1 = { userId: 'u1', activeOrganizationId: 'w1' };

  it('passes through for a local/loopback request (no auth) even on a foreign project', () => {
    const next = vi.fn();
    gate(req('p-w2'), res(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('passes a scoped request through to its own workspace project', () => {
    const next = vi.fn();
    gate(req('p-w1', w1), res(), next);
    expect(next).toHaveBeenCalledOnce();
  });

  it('404s a scoped request on another workspace project (no 403 — hides existence)', () => {
    const next = vi.fn(); const r = res();
    gate(req('p-w2', w1), r, next);
    expect(next).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(404);
    expect((r.body as any).error.code).toBe('PROJECT_NOT_FOUND');
  });

  it('404s a scoped request on a legacy/unowned project', () => {
    const next = vi.fn(); const r = res();
    gate(req('p-legacy', w1), r, next);
    expect(next).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(404);
  });

  it('404s every project for a signed-in user with no active workspace', () => {
    const next = vi.fn(); const r = res();
    gate(req('p-w1', { userId: 'u9', activeOrganizationId: null }), r, next);
    expect(next).not.toHaveBeenCalled();
    expect(r.statusCode).toBe(404);
  });

  it('passes a missing project through so the handler returns its own 404', () => {
    const next = vi.fn();
    gate(req('does-not-exist', w1), res(), next);
    expect(next).toHaveBeenCalledOnce();
  });
});
