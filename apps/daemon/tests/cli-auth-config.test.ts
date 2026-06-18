// Phase 4 — client-side CLI auth config (~/.open-design/config.json) for
// connecting `od` to a hosted instance with a bearer token.

import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  bearerTokenFromResponse,
  clearCliAuthToken,
  readCliAuthConfig,
  resolveCliToken,
  writeCliAuthConfig,
} from '../src/cli-auth-config.js';

const dirs: string[] = [];
function envWithConfig(): NodeJS.ProcessEnv {
  const dir = mkdtempSync(join(tmpdir(), 'od-cliconf-'));
  dirs.push(dir);
  return { OD_CONFIG_FILE: join(dir, 'config.json') } as NodeJS.ProcessEnv;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

describe('CLI auth config', () => {
  it('returns empty config when the file is missing', () => {
    expect(readCliAuthConfig(envWithConfig())).toEqual({});
  });

  it('round-trips daemonUrl + token and writes 0600', () => {
    const env = envWithConfig();
    writeCliAuthConfig({ daemonUrl: 'https://od.example.com', token: 'tok123' }, env);
    expect(readCliAuthConfig(env)).toEqual({ daemonUrl: 'https://od.example.com', token: 'tok123' });
  });

  it('tolerates a corrupt config file', () => {
    const env = envWithConfig();
    writeFileSync(env.OD_CONFIG_FILE!, 'not json{', 'utf8');
    expect(readCliAuthConfig(env)).toEqual({});
  });

  it('clearCliAuthToken drops the token but keeps daemonUrl', () => {
    const env = envWithConfig();
    writeCliAuthConfig({ daemonUrl: 'https://od.example.com', token: 'tok' }, env);
    clearCliAuthToken(env);
    expect(readCliAuthConfig(env)).toEqual({ daemonUrl: 'https://od.example.com' });
  });

  it('resolveCliToken prefers the flag, falls back to stored', () => {
    const env = envWithConfig();
    writeCliAuthConfig({ token: 'stored' }, env);
    expect(resolveCliToken('flag', env)).toBe('flag');
    expect(resolveCliToken(undefined, env)).toBe('stored');
    expect(resolveCliToken(undefined, envWithConfig())).toBeNull();
  });

  it('bearerTokenFromResponse reads the set-auth-token header', () => {
    const withTok = { headers: new Headers({ 'set-auth-token': 'sess-abc' }) };
    expect(bearerTokenFromResponse(withTok)).toBe('sess-abc');
    expect(bearerTokenFromResponse({ headers: new Headers() })).toBeNull();
  });
});
