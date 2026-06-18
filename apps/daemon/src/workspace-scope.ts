import type { Request } from 'express';

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
