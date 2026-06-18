import { useEffect, useState, type ReactNode } from 'react';
import { authClient } from '../auth-client';
import { LoginScreen } from './LoginScreen';

/**
 * Gate the whole app behind login when the instance has accounts enabled.
 *
 * Probes `/api/auth/get-session` once: a 404 means auth is disabled (no
 * OPEN_DESIGN_DATABASE_URL) and the app renders normally — preserving the
 * no-accounts experience. When enabled, an unauthenticated visitor gets the
 * full login wall instead of the app; a signed-in session renders children.
 */
export function AuthGate({ children }: { children: ReactNode }) {
  const session = authClient.useSession();
  const [authEnabled, setAuthEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/auth/get-session', { headers: { origin: window.location.origin } })
      .then((res) => {
        if (!cancelled) setAuthEnabled(res.status !== 404);
      })
      .catch(() => {
        if (!cancelled) setAuthEnabled(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Auth disabled (or still probing-but-resolved-disabled): app as usual.
  if (authEnabled === false) return <>{children}</>;

  // While the enabled-state or the session is still resolving, don't flash the
  // login wall — render the app's normal loading path (children handle their
  // own loading) only once we know auth is off; otherwise wait.
  if (authEnabled === null || session.isPending) return <>{children}</>;

  if (!session.data?.user) {
    return <LoginScreen onAuthed={() => void session.refetch()} />;
  }

  return <>{children}</>;
}
