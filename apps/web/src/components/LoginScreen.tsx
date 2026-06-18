import { useState, type FormEvent } from 'react';
import { Button } from '@open-design/components';
import { authClient } from '../auth-client';
import { useT } from '../i18n';
import styles from './LoginScreen.module.css';

type PwMode = 'sign-in' | 'sign-up';

/**
 * Full-screen login wall shown by AuthGate when the instance has accounts
 * enabled and no one is signed in. Offers all three methods: email+password,
 * Google OAuth, and email 6-digit code. `onAuthed` re-checks the session.
 */
export function LoginScreen({ onAuthed }: { onAuthed: () => void }) {
  const t = useT();
  const [method, setMethod] = useState<'password' | 'otp'>('password');
  const [pwMode, setPwMode] = useState<PwMode>('sign-in');
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [codeSent, setCodeSent] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function run(fn: () => Promise<{ error?: { message?: string } | null }>, after?: () => void) {
    setPending(true);
    setError(null);
    try {
      const result = await fn();
      if (result?.error) {
        setError(result.error.message || t('auth.failed'));
        return;
      }
      after ? after() : onAuthed();
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : t('auth.failed'));
    } finally {
      setPending(false);
    }
  }

  function handlePassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(() =>
      pwMode === 'sign-in'
        ? authClient.signIn.email({ email: email.trim(), password })
        : authClient.signUp.email({ email: email.trim(), password, name: name.trim() || email.trim() }),
    );
  }

  function handleSendCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(
      () => authClient.emailOtp.sendVerificationOtp({ email: email.trim(), type: 'sign-in' }),
      () => setCodeSent(true),
    );
  }

  function handleVerify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void run(() => authClient.signIn.emailOtp({ email: email.trim(), otp: code.trim() }));
  }

  function handleGoogle() {
    void authClient.signIn.social({ provider: 'google', callbackURL: window.location.origin });
  }

  return (
    <div className={styles.screen} role="dialog" aria-label={t('auth.loginTitle')} aria-modal>
      <div className={styles.card}>
        <h1 className={styles.title}>{t('auth.loginTitle')}</h1>
        <p className={styles.subtitle}>{t('auth.loginSubtitle')}</p>

        {method === 'password' ? (
          <>
            <div className={styles.modes} role="tablist" aria-label={t('auth.modeLabel')}>
              <button
                type="button"
                role="tab"
                aria-selected={pwMode === 'sign-in'}
                className={pwMode === 'sign-in' ? `${styles.modeButton} ${styles.modeButtonActive}` : styles.modeButton}
                onClick={() => { setPwMode('sign-in'); setError(null); }}
              >
                {t('auth.signIn')}
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={pwMode === 'sign-up'}
                className={pwMode === 'sign-up' ? `${styles.modeButton} ${styles.modeButtonActive}` : styles.modeButton}
                onClick={() => { setPwMode('sign-up'); setError(null); }}
              >
                {t('auth.create')}
              </button>
            </div>
            <form className={styles.field} onSubmit={handlePassword} style={{ display: 'grid', gap: 12 }}>
              {pwMode === 'sign-up' ? (
                <label className={styles.field}>
                  <span>{t('auth.name')}</span>
                  <input autoComplete="name" value={name} onChange={(e) => setName(e.currentTarget.value)} />
                </label>
              ) : null}
              <label className={styles.field}>
                <span>{t('auth.email')}</span>
                <input type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} />
              </label>
              <label className={styles.field}>
                <span>{t('auth.password')}</span>
                <input
                  type="password"
                  required
                  minLength={8}
                  autoComplete={pwMode === 'sign-in' ? 'current-password' : 'new-password'}
                  value={password}
                  onChange={(e) => setPassword(e.currentTarget.value)}
                />
              </label>
              {error ? <p className={styles.error}>{error}</p> : null}
              <Button type="submit" className={styles.submit} disabled={pending}>
                {pending ? t('auth.working') : pwMode === 'sign-in' ? t('auth.signIn') : t('auth.createAccount')}
              </Button>
            </form>
          </>
        ) : (
          <form onSubmit={codeSent ? handleVerify : handleSendCode} style={{ display: 'grid', gap: 12 }}>
            <label className={styles.field}>
              <span>{t('auth.email')}</span>
              <input type="email" required autoComplete="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} disabled={codeSent} />
            </label>
            {codeSent ? (
              <label className={styles.field}>
                <span>{t('auth.codeLabel')}</span>
                <input inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.currentTarget.value)} />
              </label>
            ) : null}
            {error ? <p className={styles.error}>{error}</p> : null}
            <Button type="submit" className={styles.submit} disabled={pending}>
              {pending ? t('auth.working') : codeSent ? t('auth.verify') : t('auth.sendCode')}
            </Button>
          </form>
        )}

        <div className={styles.divider}>{t('auth.or')}</div>
        <Button className={styles.oauth} disabled={pending} onClick={handleGoogle}>
          {t('auth.continueWithGoogle')}
        </Button>
        <button
          type="button"
          className={styles.linkButton}
          onClick={() => { setMethod(method === 'password' ? 'otp' : 'password'); setError(null); setCodeSent(false); }}
        >
          {method === 'password' ? t('auth.emailCode') : t('auth.back')}
        </button>
      </div>
    </div>
  );
}
