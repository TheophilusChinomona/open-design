// buildAuthOptions assembles the better-auth options (plugins, social, OTP,
// cookies) from an AuthConfig — pure, no DB. Phase 1, Task 1.3.

import { describe, expect, it } from 'vitest';
import { buildAuthOptions } from '../src/routes/auth.js';
import type { AuthConfig } from '../src/routes/auth-config.js';
import { createEmailSender } from '../src/auth-email.js';

function cfg(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return {
    databaseUrl: 'postgres://x',
    secret: '',
    trustedOriginsStatic: [],
    useSecureCookies: false,
    signupMode: 'open',
    email: { mode: 'log' },
    ...overrides,
  };
}

const sender = createEmailSender({ mode: 'log' }, { log: () => {} });

describe('buildAuthOptions', () => {
  it('enables email+password and wires the foundation plugins', () => {
    const opts = buildAuthOptions(cfg(), 'secret', sender);
    expect(opts.emailAndPassword?.enabled).toBe(true);
    const ids = (opts.plugins ?? []).map((p) => p.id);
    // device-authorization is added in Phase 4 (CLI); bearer covers token auth here.
    expect(ids).toEqual(expect.arrayContaining(['organization', 'email-otp', 'bearer']));
  });

  it('adds Google social provider only when configured', () => {
    expect(buildAuthOptions(cfg(), 's', sender).socialProviders?.google).toBeUndefined();
    const withGoogle = buildAuthOptions(
      cfg({ google: { clientId: 'id', clientSecret: 'sec' } }),
      's',
      sender,
    );
    expect(withGoogle.socialProviders?.google).toEqual({ clientId: 'id', clientSecret: 'sec' });
  });

  it('sets baseURL and secure cookies when the config carries an https origin', () => {
    const opts = buildAuthOptions(
      cfg({ baseURL: 'https://od.example.com', useSecureCookies: true }),
      's',
      sender,
    );
    expect(opts.baseURL).toBe('https://od.example.com');
    expect((opts.advanced as { useSecureCookies?: boolean } | undefined)?.useSecureCookies).toBe(true);
  });

  it('omits baseURL/advanced for a localhost config', () => {
    const opts = buildAuthOptions(cfg(), 's', sender);
    expect(opts.baseURL).toBeUndefined();
    expect(opts.advanced).toBeUndefined();
  });

  it('trustedOrigins trusts a loopback origin but not an unlisted public one', () => {
    const opts = buildAuthOptions(cfg({ trustedOriginsStatic: ['https://od.example.com'] }), 's', sender);
    const fn = opts.trustedOrigins as (req: { headers: { get(n: string): string | null } }) => string[];
    const loopback = fn({ headers: { get: () => 'http://127.0.0.1:7456' } });
    expect(loopback).toContain('http://127.0.0.1:7456');
    expect(loopback).toContain('https://od.example.com');
    const evil = fn({ headers: { get: () => 'https://evil.example.com' } });
    expect(evil).not.toContain('https://evil.example.com');
  });
});
