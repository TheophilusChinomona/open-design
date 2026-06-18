import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

/**
 * Client-side CLI auth config — the Multica-style `~/.open-design/config.json`
 * holding the bearer token (and the daemon URL it belongs to) so `od` can drive
 * a hosted instance. The token is better-auth's session token, accepted by the
 * Phase 2 gate via the bearer plugin. Override the path with OD_CONFIG_FILE.
 */
export interface CliAuthConfig {
  daemonUrl?: string;
  token?: string;
}

export function cliConfigFile(env: NodeJS.ProcessEnv = process.env): string {
  const override = (env.OD_CONFIG_FILE ?? '').trim();
  if (override) return override;
  return join(homedir(), '.open-design', 'config.json');
}

export function readCliAuthConfig(env: NodeJS.ProcessEnv = process.env): CliAuthConfig {
  try {
    const raw = readFileSync(cliConfigFile(env), 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    if (parsed && typeof parsed === 'object') {
      const obj = parsed as Record<string, unknown>;
      const out: CliAuthConfig = {};
      if (typeof obj.daemonUrl === 'string') out.daemonUrl = obj.daemonUrl;
      if (typeof obj.token === 'string') out.token = obj.token;
      return out;
    }
    return {};
  } catch (error) {
    if (error && (error as NodeJS.ErrnoException).code === 'ENOENT') return {};
    if (error instanceof SyntaxError) return {};
    throw error;
  }
}

export function writeCliAuthConfig(config: CliAuthConfig, env: NodeJS.ProcessEnv = process.env): void {
  const file = cliConfigFile(env);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
}

export function clearCliAuthToken(env: NodeJS.ProcessEnv = process.env): void {
  const current = readCliAuthConfig(env);
  if (current.token === undefined && current.daemonUrl === undefined) {
    try {
      rmSync(cliConfigFile(env));
    } catch (error) {
      if (!(error && (error as NodeJS.ErrnoException).code === 'ENOENT')) throw error;
    }
    return;
  }
  const next: CliAuthConfig = {};
  if (current.daemonUrl !== undefined) next.daemonUrl = current.daemonUrl;
  writeCliAuthConfig(next, env);
}

/**
 * better-auth's bearer plugin returns the session token in the `set-auth-token`
 * response header on sign-in/sign-up. Pull it out for storage.
 */
export function bearerTokenFromResponse(resp: { headers: Headers }): string | null {
  const token = resp.headers.get('set-auth-token');
  return token && token.length > 0 ? token : null;
}

/** Resolve the bearer to send: explicit flag wins, else the stored token. */
export function resolveCliToken(flagToken: string | undefined, env: NodeJS.ProcessEnv = process.env): string | null {
  if (flagToken && flagToken.length > 0) return flagToken;
  return readCliAuthConfig(env).token ?? null;
}
