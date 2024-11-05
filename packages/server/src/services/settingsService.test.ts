import { assertEquals } from '@std/assert';

import { SettingsService } from './settingsService.ts';
import { convertPEMToBytes } from '../helpers/convertPEMToBytes.ts';

import { GlobalSign_Root_CA } from './defaultRootCerts/android-safetynet.ts';
import { Apple_WebAuthn_Root_CA } from './defaultRootCerts/apple.ts';

Deno.test('should accept cert as Buffer', () => {
  const gsr1Buffer = convertPEMToBytes(GlobalSign_Root_CA);
  SettingsService.setRootCertificates({
    identifier: 'android-safetynet',
    certificates: [gsr1Buffer],
  });

  const certs = SettingsService.getRootCertificates({
    identifier: 'android-safetynet',
  });

  assertEquals(certs, [GlobalSign_Root_CA]);
});

Deno.test('should accept cert as PEM string', () => {
  SettingsService.setRootCertificates({
    identifier: 'apple',
    certificates: [Apple_WebAuthn_Root_CA],
  });

  const certs = SettingsService.getRootCertificates({ identifier: 'apple' });

  assertEquals(certs, [Apple_WebAuthn_Root_CA]);
});

Deno.test('should return empty array when certificate is not set', () => {
  const certs = SettingsService.getRootCertificates({ identifier: 'none' });

  assertEquals(Array.isArray(certs), true);
  assertEquals(certs.length, 0);
});
