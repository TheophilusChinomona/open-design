import { createAuthClient } from 'better-auth/react';
import { emailOTPClient, organizationClient } from 'better-auth/client/plugins';

export const authClient = createAuthClient({
  basePath: '/api/auth',
  plugins: [emailOTPClient(), organizationClient()],
});
