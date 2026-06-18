import { configuredAllowedOrigins } from '../origin-validation.js';

export type SignupMode = 'open' | 'invite' | 'closed';

export interface AuthEmailConfig {
  mode: 'log' | 'smtp';
  smtp?: {
    host: string;
    port: number;
    user: string;
    pass: string;
    from: string;
  };
}

export interface AuthConfig {
  databaseUrl: string;
  /** Explicitly-configured secret (empty when relying on the generated one). */
  secret: string;
  /** Public origin for cookies/callbacks behind a TLS proxy; undefined for localhost. */
  baseURL?: string;
  /** Allow-list of public origins (from OD_ALLOWED_ORIGINS) trusted for CSRF. */
  trustedOriginsStatic: string[];
  useSecureCookies: boolean;
  google?: { clientId: string; clientSecret: string };
  signupMode: SignupMode;
  email: AuthEmailConfig;
}

const SIGNUP_MODES: readonly SignupMode[] = ['open', 'invite', 'closed'];

/**
 * Turn the process environment into an AuthConfig, or null when auth is
 * disabled (no OPEN_DESIGN_DATABASE_URL). Pure — no DB or network access — so
 * the policy is unit-testable. The actual secret resolution/persistence still
 * lives in createOpenDesignAuth; this only carries an explicitly-set secret.
 */
export function resolveAuthConfig(env: NodeJS.ProcessEnv): AuthConfig | null {
  const databaseUrl = (env.OPEN_DESIGN_DATABASE_URL ?? '').trim();
  if (databaseUrl.length === 0) return null;

  const allowed = configuredAllowedOrigins(env);
  const baseURL =
    (env.BETTER_AUTH_URL ?? '').trim() ||
    allowed.find((origin) => origin.startsWith('https://')) ||
    allowed[0] ||
    undefined;

  const googleId = (env.GOOGLE_CLIENT_ID ?? '').trim();
  const googleSecret = (env.GOOGLE_CLIENT_SECRET ?? '').trim();

  const signupRaw = (env.OD_AUTH_SIGNUP_MODE ?? '').trim() as SignupMode;
  const signupMode = SIGNUP_MODES.includes(signupRaw) ? signupRaw : 'open';

  const smtpHost = (env.OD_AUTH_SMTP_HOST ?? '').trim();
  const email: AuthEmailConfig = smtpHost
    ? {
        mode: 'smtp',
        smtp: {
          host: smtpHost,
          port: Number(env.OD_AUTH_SMTP_PORT ?? 587) || 587,
          user: (env.OD_AUTH_SMTP_USER ?? '').trim(),
          pass: env.OD_AUTH_SMTP_PASS ?? '',
          from: (env.OD_AUTH_SMTP_FROM ?? '').trim() || 'Open Design <no-reply@localhost>',
        },
      }
    : { mode: 'log' };

  return {
    databaseUrl,
    secret: (env.BETTER_AUTH_SECRET ?? env.AUTH_SECRET ?? '').trim(),
    // Omit (don't set to undefined) optional props — exactOptionalPropertyTypes.
    ...(baseURL ? { baseURL } : {}),
    trustedOriginsStatic: allowed,
    useSecureCookies: baseURL ? baseURL.startsWith('https://') : false,
    ...(googleId && googleSecret ? { google: { clientId: googleId, clientSecret: googleSecret } } : {}),
    signupMode,
    email,
  };
}
