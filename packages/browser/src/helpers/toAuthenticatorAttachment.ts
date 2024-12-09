import type { AuthenticatorAttachment } from '../types/index.ts';

const attachments: AuthenticatorAttachment[] = ['cross-platform', 'platform'];

/**
 * If possible coerce a `string` value into a known `AuthenticatorAttachment`
 */
export function toAuthenticatorAttachment(
  attachment: string | null,
): AuthenticatorAttachment | undefined {
  if (!attachment) {
    return;
  }

  if (attachments.indexOf(attachment as AuthenticatorAttachment) < 0) {
    return;
  }

  return attachment as AuthenticatorAttachment;
}
