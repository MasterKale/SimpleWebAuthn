import { CredentialDeviceType } from '@simplewebauthn/typescript-types';

/**
 * Make sense of Bits 3 and 4 in authenticator indicating:
 *
 * - Whether the credential can be used on multiple devices
 * - Whether the credential is backed up or not
 *
 * Invalid configurations will raise an `Error`
 */
export function parseBackupFlags({ be, bs }: { be: boolean; bs: boolean }): {
  credentialDeviceType: CredentialDeviceType;
  credentialBackedUp: boolean;
} {
  const credentialBackedUp = bs;
  let credentialDeviceType: CredentialDeviceType = 'singleDevice';

  if (be) {
    credentialDeviceType = 'multiDevice';
  }

  if (credentialDeviceType === 'singleDevice' && credentialBackedUp) {
    throw new InvalidBackupFlags(
      'Single-device credential indicated that it was backed up, which should be impossible.',
    );
  }

  return { credentialDeviceType, credentialBackedUp };
}

class InvalidBackupFlags extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidBackupFlags';
  }
}
