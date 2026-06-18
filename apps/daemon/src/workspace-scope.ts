import type { Request, RequestHandler } from 'express';

/**
 * Workspace (organization) data isolation — DB-only ownership model.
 *
 * Decision (per the auth-workspaces plan, Phase 5): we do NOT restructure the
 * on-disk RUNTIME_DATA_DIR / PROJECTS_DIR layout. A workspace dimension is
 * carried as ownership metadata (a `workspaceId` column / field) and every
 * read/write filters by the request's active workspace. This keeps the daemon
 * data-directory contract intact while isolating tenants in the DB.
 *
 * Scope resolution:
 *  - An authenticated request (the Phase 2 gate set `req.auth`) is scoped to its
 *    `activeOrganizationId` (may be null until the user picks/creates a workspace).
 *  - A loopback/local request (no `req.auth`) is unscoped: the local desktop/CLI
 *    sees everything on its own machine, exactly as today (single-tenant local).
 */
export type WorkspaceId = string;

export interface WorkspaceScope {
  /** null = unscoped (local/loopback): see everything. */
  workspaceId: WorkspaceId | null;
  scoped: boolean;
}

export function resolveWorkspaceScope(req: Pick<Request, 'auth'>): WorkspaceScope {
  const auth = req.auth;
  if (!auth) return { workspaceId: null, scoped: false };
  return { workspaceId: auth.activeOrganizationId, scoped: true };
}

export interface WorkspaceOwned {
  workspaceId?: WorkspaceId | null;
}

/**
 * Can the request's scope access a record with the given owner?
 *  - Unscoped (local) → yes (sees everything).
 *  - Scoped → only records owned by the same workspace. Legacy/unowned records
 *    (workspaceId null/undefined) are treated as belonging to no workspace and
 *    are NOT visible to a scoped request — the migration backfills them onto the
 *    default workspace so they remain reachable.
 */
export function canAccessRecord(scope: WorkspaceScope, recordWorkspaceId: WorkspaceId | null | undefined): boolean {
  if (!scope.scoped) return true;
  if (scope.workspaceId == null) return false;
  return recordWorkspaceId === scope.workspaceId;
}

/** Filter a list of owned records to those the scope may see. */
export function scopeRecords<T extends WorkspaceOwned>(scope: WorkspaceScope, records: readonly T[]): T[] {
  if (!scope.scoped) return [...records];
  return records.filter((r) => canAccessRecord(scope, r.workspaceId ?? null));
}

/** Stamp a new record with the creating request's workspace (no-op when unscoped). */
export function stampWorkspace<T extends WorkspaceOwned>(scope: WorkspaceScope, record: T): T {
  if (!scope.scoped || scope.workspaceId == null) return record;
  return { ...record, workspaceId: scope.workspaceId };
}

/** Result of looking up a record's owning workspace for the access gate. */
export interface WorkspaceLookup {
  /** Whether the record exists at all (false → let the downstream handler 404). */
  exists: boolean;
  workspaceId: WorkspaceId | null;
}

/**
 * Express middleware that enforces workspace ownership for a single resource
 * addressed by `req.params[idParam]` (default `id`). Mount it on a parameterised
 * path prefix (e.g. `/api/projects/:id`) so it also covers every sub-resource
 * under that record in one place.
 *
 * Behaviour:
 *  - Unscoped (local/loopback) requests pass through untouched.
 *  - For a scoped request, a record owned by another workspace (or a
 *    legacy/unowned record with no workspaceId, or any record when the request
 *    has no active workspace) responds 404 — NOT 403 — so cross-tenant probes
 *    can't even confirm a record exists.
 *  - A missing record passes through so the existing handler returns its own 404.
 */
export function createProjectWorkspaceGate(
  lookup: (id: string) => WorkspaceLookup,
  idParam = 'id',
): RequestHandler {
  return (req, res, next) => {
    const scope = resolveWorkspaceScope(req);
    if (!scope.scoped) return next();
    const raw = req.params[idParam];
    const id = Array.isArray(raw) ? raw[0] : raw;
    if (!id) return next();
    const record = lookup(id);
    if (!record.exists) return next();
    if (canAccessRecord(scope, record.workspaceId)) return next();
    res.status(404).json({ error: { code: 'PROJECT_NOT_FOUND', message: 'not found' } });
  };
}
