import fs from 'fs';
import path from 'path';

import { SettingsService } from './settingsService';

import { GlobalSign_Root_CA } from './defaultRootCerts/android-safetynet';
import { Apple_WebAuthn_Root_CA } from './defaultRootCerts/apple';

function pemToBuffer(pem: string): Buffer {
  const trimmed = pem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace('\n', '');
  return Buffer.from(trimmed, 'base64');
}

describe('setRootCertificate/getRootCertificate', () => {
  test('should accept cert as Buffer', () => {
    const gsr1Buffer = pemToBuffer(GlobalSign_Root_CA);
    SettingsService.setRootCertificates({
      identifier: 'android-safetynet',
      certificates: [gsr1Buffer],
    });

    const certs = SettingsService.getRootCertificates({ identifier: 'android-safetynet' });

    expect(certs).toEqual([GlobalSign_Root_CA]);
  });

  test('should accept cert as PEM string', () => {
    SettingsService.setRootCertificates({
      identifier: 'apple',
      certificates: [Apple_WebAuthn_Root_CA],
    });

    const certs = SettingsService.getRootCertificates({ identifier: 'apple' });

    expect(certs).toEqual([Apple_WebAuthn_Root_CA]);
  });

  test('should return empty array when certificate is not set', () => {
    const certs = SettingsService.getRootCertificates({ identifier: 'none' });

    expect(Array.isArray(certs)).toEqual(true);
    expect(certs.length).toEqual(0);
  });
});
