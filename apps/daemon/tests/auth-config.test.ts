// Pure env→config resolution for the better-auth plugin layer. No DB, no
// network — just the policy that turns env vars into an AuthConfig (or null
// when auth is disabled). Phase 1, Task 1.1 of the auth-workspaces plan.

import { describe, expect, it } from 'vitest';
import { resolveAuthConfig } from '../src/routes/auth-config.js';

const DB = 'postgres://x';

describe('resolveAuthConfig', () => {
  it('returns null when no database url', () => {
    expect(resolveAuthConfig({} as NodeJS.ProcessEnv)).toBeNull();
  });

  it('derives baseURL + secure cookies from the https OD_ALLOWED_ORIGINS entry', () => {
    const c = resolveAuthConfig({
      OPEN_DESIGN_DATABASE_URL: DB,
      BETTER_AUTH_SECRET: 's',
      OD_ALLOWED_ORIGINS: 'http://127.0.0.1:7456,https://od.example.com',
    } as NodeJS.ProcessEnv)!;
    expect(c.baseURL).toBe('https://od.example.com');
    expect(c.useSecureCookies).toBe(true);
    expect(c.trustedOriginsStatic).toContain('https://od.example.com');
  });

  it('leaves baseURL unset and cookies insecure for pure localhost', () => {
    const c = resolveAuthConfig({ OPEN_DESIGN_DATABASE_URL: DB } as NodeJS.ProcessEnv)!;
    expect(c.baseURL).toBeUndefined();
    expect(c.useSecureCookies).toBe(false);
  });

  it('BETTER_AUTH_URL overrides the derived baseURL', () => {
    const c = resolveAuthConfig({
      OPEN_DESIGN_DATABASE_URL: DB,
      OD_ALLOWED_ORIGINS: 'https://a.example.com',
      BETTER_AUTH_URL: 'https://b.example.com',
    } as NodeJS.ProcessEnv)!;
    expect(c.baseURL).toBe('https://b.example.com');
  });

  it('enables google only when both client id and secret are present', () => {
    const base = { OPEN_DESIGN_DATABASE_URL: DB } as NodeJS.ProcessEnv;
    expect(resolveAuthConfig(base)!.google).toBeUndefined();
    expect(resolveAuthConfig({ ...base, GOOGLE_CLIENT_ID: 'id' } as NodeJS.ProcessEnv)!.google).toBeUndefined();
    expect(
      resolveAuthConfig({ ...base, GOOGLE_CLIENT_ID: 'id', GOOGLE_CLIENT_SECRET: 'sec' } as NodeJS.ProcessEnv)!.google,
    ).toEqual({ clientId: 'id', clientSecret: 'sec' });
  });

  it('defaults signupMode to open and reads OD_AUTH_SIGNUP_MODE (validating the enum)', () => {
    const base = { OPEN_DESIGN_DATABASE_URL: DB } as NodeJS.ProcessEnv;
    expect(resolveAuthConfig(base)!.signupMode).toBe('open');
    expect(resolveAuthConfig({ ...base, OD_AUTH_SIGNUP_MODE: 'invite' } as NodeJS.ProcessEnv)!.signupMode).toBe('invite');
    expect(resolveAuthConfig({ ...base, OD_AUTH_SIGNUP_MODE: 'closed' } as NodeJS.ProcessEnv)!.signupMode).toBe('closed');
    // Unknown value falls back to open.
    expect(resolveAuthConfig({ ...base, OD_AUTH_SIGNUP_MODE: 'bogus' } as NodeJS.ProcessEnv)!.signupMode).toBe('open');
  });

  it('chooses log email mode without SMTP host, smtp mode with it', () => {
    const base = { OPEN_DESIGN_DATABASE_URL: DB } as NodeJS.ProcessEnv;
    expect(resolveAuthConfig(base)!.email.mode).toBe('log');
    const smtp = resolveAuthConfig({
      ...base,
      OD_AUTH_SMTP_HOST: 'smtp.example.com',
      OD_AUTH_SMTP_PORT: '2525',
      OD_AUTH_SMTP_FROM: 'OD <no-reply@example.com>',
    } as NodeJS.ProcessEnv)!;
    expect(smtp.email.mode).toBe('smtp');
    expect(smtp.email.smtp?.port).toBe(2525);
    expect(smtp.email.smtp?.from).toBe('OD <no-reply@example.com>');
  });
});
