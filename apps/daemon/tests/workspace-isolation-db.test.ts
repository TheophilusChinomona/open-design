// Phase 5 — workspace isolation, integration proof against a REAL SQLite db
// and a REAL Express server over loopback HTTP. This exercises the parts unit
// tests can't: that `workspaceId` survives the metadata_json JSON round-trip,
// and that the real createProjectWorkspaceGate + resolveWorkspaceScope +
// canAccessRecord enforce isolation end-to-end over HTTP.
//
// req.auth is injected by a test middleware that plays the exact role the
// production auth gate (auth-context.ts) plays for a hosted request — it is the
// harness standing in for an authenticated non-loopback peer, NOT a product
// backdoor. No network exposure: the server binds 127.0.0.1.

import express from 'express';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { closeDatabase, getProject, insertProject, listProjects, openDatabase } from '../src/db.js';
import {
  canAccessRecord,
  createProjectWorkspaceGate,
  resolveWorkspaceScope,
} from '../src/workspace-scope.js';

describe('workspace isolation (real db + http)', () => {
  let tempDir: string;
  let server: import('node:http').Server;
  let base: string;

  beforeEach(async () => {
    tempDir = mkdtempSync(path.join(os.tmpdir(), 'od-ws-iso-'));
    const db = openDatabase(tempDir, { dataDir: tempDir });
    const now = Date.now();
    const seed = (id: string, workspaceId: string | null) =>
      insertProject(db, {
        id,
        name: id,
        metadata: workspaceId ? { kind: 'prototype', workspaceId } : { kind: 'prototype' },
        createdAt: now,
        updatedAt: now,
      } as any);
    seed('p-a', 'w1');
    seed('p-b', 'w2');
    seed('p-legacy', null);

    const app = express();
    // Stand in for the production auth gate: an `x-test-ws` header → req.auth.
    app.use((req, _res, next) => {
      const ws = req.headers['x-test-ws'];
      if (typeof ws === 'string') {
        (req as any).auth = { userId: 'u', activeOrganizationId: ws === 'none' ? null : ws };
      }
      next();
    });
    // The REAL gate, mounted exactly as project-routes.ts mounts it.
    app.use('/api/projects/:id', createProjectWorkspaceGate((id) => {
      const p = getProject(db, id);
      return { exists: Boolean(p), workspaceId: (p as any)?.metadata?.workspaceId ?? null };
    }));
    app.get('/api/projects/:id', (_req, res) => res.json({ ok: true }));
    app.get('/api/projects', (req, res) => {
      const scope = resolveWorkspaceScope(req as any);
      res.json({
        projects: listProjects(db)
          .filter((p: any) => canAccessRecord(scope, p.metadata?.workspaceId ?? null))
          .map((p: any) => ({ id: p.id })),
      });
    });

    server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve, reject) => {
      server.once('listening', () => resolve());
      server.once('error', reject);
    });
    const addr = server.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    base = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(() => {
    server?.close();
    closeDatabase();
    rmSync(tempDir, { recursive: true, force: true });
  });

  const listIds = async (ws?: string) => {
    const res = await fetch(`${base}/api/projects`, ws ? { headers: { 'x-test-ws': ws } } : undefined);
    const body = (await res.json()) as { projects: { id: string }[] };
    return body.projects.map((p) => p.id).sort();
  };
  const getStatus = async (id: string, ws?: string) =>
    (await fetch(`${base}/api/projects/${id}`, ws ? { headers: { 'x-test-ws': ws } } : undefined)).status;

  it('round-trips workspaceId through metadata_json (db)', () => {
    const db = openDatabase(tempDir, { dataDir: tempDir });
    expect((getProject(db, 'p-a') as any)?.metadata?.workspaceId).toBe('w1');
    expect((getProject(db, 'p-legacy') as any)?.metadata?.workspaceId ?? null).toBeNull();
  });

  it('a workspace member lists only its own projects', async () => {
    expect(await listIds('w1')).toEqual(['p-a']);
    expect(await listIds('w2')).toEqual(['p-b']);
  });

  it('a local/loopback (unscoped) request lists every project incl. legacy', async () => {
    expect(await listIds()).toEqual(['p-a', 'p-b', 'p-legacy']);
  });

  it('GET on own project is 200, on another workspace or legacy is 404', async () => {
    expect(await getStatus('p-a', 'w1')).toBe(200);
    expect(await getStatus('p-b', 'w1')).toBe(404);
    expect(await getStatus('p-legacy', 'w1')).toBe(404);
  });

  it('a signed-in user with no active workspace sees nothing', async () => {
    expect(await listIds('none')).toEqual([]);
    expect(await getStatus('p-a', 'none')).toBe(404);
  });
});
