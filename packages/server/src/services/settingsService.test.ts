import fs from 'fs';
import path from 'path';

import settingsService from './settingsService';

import GSR1 from './defaultRootCerts/GSR1';
import Apple_WebAuthn_Root_CA from './defaultRootCerts/Apple_WebAuthn_Root_CA';

function pemToBuffer(pem: string): Buffer {
  const trimmed = pem
    .replace('-----BEGIN CERTIFICATE-----', '')
    .replace('-----END CERTIFICATE-----', '')
    .replace('\n', '');
  return Buffer.from(trimmed, 'base64');
}

describe('setRootCertificate/getRootCertificate', () => {
  test('should accept cert as Buffer', () => {
    const gsr1Buffer = pemToBuffer(GSR1);
    settingsService.setRootCertificates({
      attestationFormat: 'android-safetynet',
      certificates: [gsr1Buffer],
    });

    const certs = settingsService.getRootCertificates({ attestationFormat: 'android-safetynet' });

    expect(certs).toEqual([GSR1]);
  });

  test('should accept cert as PEM string', () => {
    settingsService.setRootCertificates({
      attestationFormat: 'apple',
      certificates: [Apple_WebAuthn_Root_CA],
    });

    const certs = settingsService.getRootCertificates({ attestationFormat: 'apple' });

    expect(certs).toEqual([Apple_WebAuthn_Root_CA]);
  });

  test('should return empty array when certificate is not set', () => {
    const certs = settingsService.getRootCertificates({ attestationFormat: 'none' });

    expect(Array.isArray(certs)).toEqual(true);
    expect(certs.length).toEqual(0);
  });
});
