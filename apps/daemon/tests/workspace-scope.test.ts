// Phase 5 — workspace (organization) data isolation, DB-only ownership model.
// Pure logic: resolve a request's scope, filter/stamp owned records.

import { describe, expect, it } from 'vitest';
import {
  canAccessRecord,
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
