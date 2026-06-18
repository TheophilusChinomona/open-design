// OTP email sender: log mode (dev / self-host without SMTP) and smtp mode.
// Phase 1, Task 1.2 of the auth-workspaces plan.

import { describe, expect, it, vi } from 'vitest';
import { createEmailSender } from '../src/auth-email.js';

describe('createEmailSender', () => {
  it('log mode writes the recipient and code to the injected sink', async () => {
    const sink = vi.fn();
    const sender = createEmailSender({ mode: 'log' }, { log: sink });
    await sender.sendOtp('user@example.com', '123456');
    expect(sink).toHaveBeenCalledTimes(1);
    const msg = sink.mock.calls[0]![0] as string;
    expect(msg).toContain('user@example.com');
    expect(msg).toContain('123456');
  });

  it('log mode does not throw with the default sink', async () => {
    const sender = createEmailSender({ mode: 'log' });
    await expect(sender.sendOtp('a@b.co', '000000')).resolves.toBeUndefined();
  });

  it('smtp mode constructs without throwing and exposes sendOtp', () => {
    const sender = createEmailSender({
      mode: 'smtp',
      smtp: { host: 'smtp.example.com', port: 587, user: 'u', pass: 'p', from: 'OD <no-reply@example.com>' },
    });
    expect(typeof sender.sendOtp).toBe('function');
  });
});
