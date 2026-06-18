import express from 'express';
import type { Express } from 'express';
import { betterAuth } from 'better-auth';
import type { BetterAuthOptions } from 'better-auth';
import { toNodeHandler } from 'better-auth/node';
import { bearer, emailOTP, organization } from 'better-auth/plugins';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Pool } from 'pg';
import { isLoopbackOrPrivateLanHost } from '../origin-validation.js';
import { resolveAuthConfig, type AuthConfig } from './auth-config.js';
import { createEmailSender, type EmailSender } from '../auth-email.js';

const AUTH_SECRET_FILE = 'auth-secret';

export type OpenDesignAuth = ReturnType<typeof betterAuth>;

export type OpenDesignAuthRuntime = {
  handler: express.RequestHandler;
  /** The better-auth instance — used by the request-auth gate (Phase 2). */
  auth: OpenDesignAuth;
  shutdown: () => Promise<void>;
};

/**
 * Assemble the better-auth options (plugins, social providers, OTP email,
 * trusted origins, secure cookies) from a resolved AuthConfig. Pure: no DB,
 * no network — the `database` is attached separately by createOpenDesignAuth.
 */
export function buildAuthOptions(
  config: AuthConfig,
  secret: string,
  emailSender: EmailSender,
): BetterAuthOptions {
  const allowedOrigins = config.trustedOriginsStatic;
  return {
    appName: 'Open Design',
    basePath: '/api/auth',
    ...(config.baseURL ? { baseURL: config.baseURL } : {}),
    secret,
    emailAndPassword: { enabled: true },
    ...(config.google ? { socialProviders: { google: config.google } } : {}),
    // device-authorization (the CLI browser-approval flow) is wired in Phase 4
    // where its verificationUri/expiry are configured; bearer is enough here to
    // let the API accept `Authorization: Bearer <token>`.
    plugins: [
      organization(),
      bearer(),
      emailOTP({
        async sendVerificationOTP({ email, otp }) {
          await emailSender.sendOtp(email, otp);
        },
      }),
    ],
    // CSRF: public origins must be explicitly allow-listed via
    // OD_ALLOWED_ORIGINS — never blanket-echo the request Origin. Loopback /
    // private-LAN origins are trusted so the local web UI and the `od` CLI
    // (dynamic ports) work without per-port config; the daemon's own origin
    // guard already gates those.
    trustedOrigins: (request) => {
      const origin = request?.headers.get('origin');
      if (!origin) return allowedOrigins;
      try {
        const parsed = new URL(origin);
        if (isLoopbackOrPrivateLanHost(parsed.hostname)) {
          return [...allowedOrigins, parsed.origin];
        }
      } catch {
        return allowedOrigins;
      }
      return allowedOrigins;
    },
    ...(config.useSecureCookies ? { advanced: { useSecureCookies: true } } : {}),
  };
}

export interface RegisterAuthRoutesDeps {
  dataDir: string;
  env?: NodeJS.ProcessEnv;
}

/**
 * Mount the better-auth email/password endpoints under `/api/auth/*`.
 *
 * Must be called BEFORE `express.json()` is installed on the app: better-auth
 * owns its own body parsing and breaks if the body is consumed upstream.
 *
 * Returns the runtime handle (carrying the `pg` pool's shutdown) so the caller
 * can close it during daemon teardown, or `null` when auth is disabled (no
 * `OPEN_DESIGN_DATABASE_URL` configured).
 */
export async function registerAuthRoutes(
  app: Express,
  deps: RegisterAuthRoutesDeps,
): Promise<OpenDesignAuthRuntime | null> {
  let runtime: OpenDesignAuthRuntime | null;
  try {
    runtime = await createOpenDesignAuth(deps);
  } catch (error) {
    // Auth was configured (OPEN_DESIGN_DATABASE_URL set) but the database is
    // unreachable. Do NOT crash the daemon — and do NOT silently disable auth
    // (that would fail OPEN on a hosted instance). Start in "locked" mode: the
    // /api/auth routes stay unmounted and the API gate fails CLOSED (503) until
    // the DB recovers and the daemon is restarted. authConfigured() lets the
    // gate tell this apart from a genuinely auth-less instance.
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(
      `[auth] backend unavailable — starting in LOCKED mode; gated /api will 503 until the DB is reachable and the daemon restarts: ${message}\n`,
    );
    return null;
  }
  if (runtime) {
    app.all('/api/auth/*splat', runtime.handler);
  }
  return runtime;
}

/** Whether auth is configured at all (OPEN_DESIGN_DATABASE_URL set). Lets the
 *  gate distinguish "no accounts" (open) from "configured but DB down" (locked). */
export function isAuthConfigured(env: NodeJS.ProcessEnv = process.env): boolean {
  return resolveAuthConfig(env) != null;
}

export async function createOpenDesignAuth(options: {
  dataDir: string;
  env?: NodeJS.ProcessEnv;
}): Promise<OpenDesignAuthRuntime | null> {
  const env = options.env ?? process.env;
  const config = resolveAuthConfig(env);
  if (!config) return null;

  const pool = new Pool({ connectionString: config.databaseUrl });
  try {
    // Tolerate a brief DB blip on boot (e.g. the tunnel/DB coming up a moment
    // after the daemon): retry the schema ensure before giving up. A genuine
    // outage still throws → registerAuthRoutes catches it (locked mode).
    await ensureSchemaWithRetry(pool);
  } catch (error) {
    await pool.end().catch(() => {});
    throw error;
  }

  const emailSender = createEmailSender(config.email);
  const secret = config.secret || resolveAuthSecret(options.dataDir, env);
  const authOptions: BetterAuthOptions = {
    ...buildAuthOptions(config, secret, emailSender),
    database: pool,
  };
  const auth = betterAuth(authOptions);
  const nodeHandler = toNodeHandler(auth);

  return {
    handler: (req, res) => nodeHandler(req, res),
    auth,
    shutdown: async () => {
      await pool.end();
    },
  };
}

function resolveAuthSecret(dataDir: string, env: NodeJS.ProcessEnv): string {
  const configured = (env.BETTER_AUTH_SECRET ?? env.AUTH_SECRET ?? '').trim();
  if (configured.length > 0) return configured;

  fs.mkdirSync(dataDir, { recursive: true });
  const secretPath = path.join(dataDir, AUTH_SECRET_FILE);
  try {
    const existing = fs.readFileSync(secretPath, 'utf8').trim();
    if (existing.length > 0) return existing;
  } catch (error) {
    if (!isNodeErrorWithCode(error, 'ENOENT')) throw error;
  }

  const secret = randomBytes(32).toString('base64url');
  fs.writeFileSync(secretPath, `${secret}\n`, { mode: 0o600 });
  return secret;
}

function isNodeErrorWithCode(error: unknown, code: string): error is NodeJS.ErrnoException {
  return typeof error === 'object' && error !== null && 'code' in error && error.code === code;
}

async function ensureSchemaWithRetry(pool: Pool): Promise<void> {
  const attempts = Math.max(1, Number(process.env.OD_AUTH_DB_RETRIES ?? 5) || 5);
  const delayMs = Math.max(0, Number(process.env.OD_AUTH_DB_RETRY_MS ?? 1500) || 1500);
  let lastError: unknown;
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      await ensureBetterAuthPostgresSchema(pool);
      return;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        process.stderr.write(`[auth] DB not ready (attempt ${attempt}/${attempts}), retrying in ${delayMs}ms…\n`);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }
  throw lastError;
}

async function ensureBetterAuthPostgresSchema(pool: Pool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS "user" (
      "id" text PRIMARY KEY,
      "name" text NOT NULL,
      "email" text NOT NULL UNIQUE,
      "emailVerified" boolean NOT NULL DEFAULT false,
      "image" text,
      "createdAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS "session" (
      "id" text PRIMARY KEY,
      "expiresAt" timestamp NOT NULL,
      "token" text NOT NULL UNIQUE,
      "createdAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "ipAddress" text,
      "userAgent" text,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS "session_userId_idx" ON "session"("userId");

    CREATE TABLE IF NOT EXISTS "account" (
      "id" text PRIMARY KEY,
      "accountId" text NOT NULL,
      "providerId" text NOT NULL,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "accessToken" text,
      "refreshToken" text,
      "idToken" text,
      "accessTokenExpiresAt" timestamp,
      "refreshTokenExpiresAt" timestamp,
      "scope" text,
      "password" text,
      "createdAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS "account_userId_idx" ON "account"("userId");

    CREATE TABLE IF NOT EXISTS "verification" (
      "id" text PRIMARY KEY,
      "identifier" text NOT NULL,
      "value" text NOT NULL,
      "expiresAt" timestamp NOT NULL,
      "createdAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
      "updatedAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS "verification_identifier_idx" ON "verification"("identifier");

    -- organization plugin: workspaces + members + invitations.
    CREATE TABLE IF NOT EXISTS "organization" (
      "id" text PRIMARY KEY,
      "name" text NOT NULL,
      "slug" text UNIQUE,
      "logo" text,
      "metadata" text,
      "createdAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS "member" (
      "id" text PRIMARY KEY,
      "organizationId" text NOT NULL REFERENCES "organization"("id") ON DELETE CASCADE,
      "userId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
      "role" text NOT NULL DEFAULT 'member',
      "createdAt" timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS "member_organizationId_idx" ON "member"("organizationId");
    CREATE INDEX IF NOT EXISTS "member_userId_idx" ON "member"("userId");

    CREATE TABLE IF NOT EXISTS "invitation" (
      "id" text PRIMARY KEY,
      "organizationId" text NOT NULL REFERENCES "organization"("id") ON DELETE CASCADE,
      "email" text NOT NULL,
      "role" text,
      "status" text NOT NULL DEFAULT 'pending',
      "expiresAt" timestamp NOT NULL,
      "inviterId" text NOT NULL REFERENCES "user"("id") ON DELETE CASCADE
    );
    CREATE INDEX IF NOT EXISTS "invitation_organizationId_idx" ON "invitation"("organizationId");
    CREATE INDEX IF NOT EXISTS "invitation_email_idx" ON "invitation"("email");

    -- The active workspace for a session (set by the organization plugin).
    ALTER TABLE "session" ADD COLUMN IF NOT EXISTS "activeOrganizationId" text;
  `);
}
