// @vitest-environment jsdom
//
// AuthGate decides whether to show the app or the login wall, based on a
// /api/auth/get-session probe (404 = auth disabled) + the better-auth session.

import { cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthGate } from '../../src/components/AuthGate';

const h = vi.hoisted(() => ({
  session: { data: null as { user?: unknown } | null, isPending: false, refetch: vi.fn() },
}));

vi.mock('../../src/auth-client', () => ({
  authClient: {
    useSession: () => h.session,
    signIn: { email: vi.fn(), social: vi.fn(), emailOtp: vi.fn() },
    signUp: { email: vi.fn() },
    emailOtp: { sendVerificationOtp: vi.fn() },
  },
}));

function mockProbe(status: number) {
  vi.stubGlobal('fetch', vi.fn(async () => ({ status }) as Response));
}

describe('AuthGate', () => {
  beforeEach(() => {
    h.session.data = null;
    h.session.isPending = false;
  });
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it('renders the app (children) when auth is disabled (probe 404)', async () => {
    mockProbe(404);
    render(<AuthGate><div>APP CONTENT</div></AuthGate>);
    expect(await screen.findByText('APP CONTENT')).toBeTruthy();
    expect(screen.queryByRole('dialog', { name: 'Sign in to Open Design' })).toBeNull();
  });

  it('shows the login wall when auth is enabled and signed out', async () => {
    mockProbe(200);
    render(<AuthGate><div>APP CONTENT</div></AuthGate>);
    await waitFor(() => expect(screen.getByRole('dialog', { name: 'Sign in to Open Design' })).toBeTruthy());
    expect(screen.queryByText('APP CONTENT')).toBeNull();
  });

  it('renders the app when a session is present', async () => {
    mockProbe(200);
    h.session.data = { user: { id: 'u1' } };
    render(<AuthGate><div>APP CONTENT</div></AuthGate>);
    expect(await screen.findByText('APP CONTENT')).toBeTruthy();
  });
});
