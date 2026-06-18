import type { AuthEmailConfig } from './routes/auth-config.js';

export interface EmailSender {
  sendOtp(to: string, code: string): Promise<void>;
}

export interface EmailSenderOptions {
  /** Override the log sink (defaults to stderr). Used by tests. */
  log?: (message: string) => void;
}

/**
 * Build an OTP email sender from config.
 *
 * - `log` mode (no SMTP configured): writes the code to stderr so a dev or
 *   self-host operator without an email provider can still complete the
 *   email-code login by reading the daemon logs.
 * - `smtp` mode: lazily imports `nodemailer` (kept out of the hot path and
 *   optional at install time) and sends a plain-text OTP message.
 */
export function createEmailSender(config: AuthEmailConfig, options: EmailSenderOptions = {}): EmailSender {
  if (config.mode === 'smtp' && config.smtp) {
    const smtp = config.smtp;
    return {
      async sendOtp(to: string, code: string): Promise<void> {
        const nodemailer = await import('nodemailer');
        const transport = nodemailer.createTransport({
          host: smtp.host,
          port: smtp.port,
          secure: smtp.port === 465,
          auth: smtp.user ? { user: smtp.user, pass: smtp.pass } : undefined,
        });
        await transport.sendMail({
          from: smtp.from,
          to,
          subject: 'Your Open Design sign-in code',
          text: `Your Open Design verification code is ${code}. It expires shortly. If you didn't request it, ignore this email.`,
        });
      },
    };
  }

  const log = options.log ?? ((message: string) => process.stderr.write(`${message}\n`));
  return {
    async sendOtp(to: string, code: string): Promise<void> {
      log(`[auth-email] OTP for ${to}: ${code} (set OD_AUTH_SMTP_HOST to deliver real emails)`);
    },
  };
}
