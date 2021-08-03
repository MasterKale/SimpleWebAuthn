import fs from 'fs';
import path from 'path';

import { AttestationFormat } from '../helpers/decodeAttestationObject';
import convertCertBufferToPEM from '../helpers/convertCertBufferToPEM';

class SettingsService {
  // Certificates are stored as PEM-formatted strings
  private pemCertificates: Map<AttestationFormat, string[]>;

  constructor() {
    this.pemCertificates = new Map();
  }

  /**
   * Set potential root certificates for attestation formats that use them. Root certs will be tried
   * one-by-one when validating a certificate path.
   *
   * Certificates can be specified as a raw `Buffer`, or as a PEM-formatted string. If a
   * `Buffer` is passed in it will be converted to PEM format.
   */
  setRootCertificates(opts: {
    attestationFormat: AttestationFormat;
    certificates: (Buffer | string)[];
  }): void {
    const { attestationFormat, certificates } = opts;

    const newCertificates: string[] = [];
    for (const cert of certificates) {
      if (cert instanceof Buffer) {
        newCertificates.push(convertCertBufferToPEM(cert));
      } else {
        newCertificates.push(cert);
      }
    }

    this.pemCertificates.set(attestationFormat, newCertificates);
  }

  /**
   * Get any registered root certificates for the specified attestation format
   */
  getRootCertificates(opts: { attestationFormat: AttestationFormat }): string[] {
    const { attestationFormat } = opts;
    return this.pemCertificates.get(attestationFormat) ?? [];
  }
}

const settingsService = new SettingsService();

// Initialize default certificates
/**
 * Google GlobalSign R2
 *
 * Downloaded from https://pki.goog/gsr2/GSR2.crt
 *
 * Valid until 2021-12-15 @ 00:00 PST
 */
settingsService.setRootCertificates({
  attestationFormat: 'android-safetynet',
  certificates: [fs.readFileSync(path.resolve(__dirname, './defaultRootCerts/GSR2.crt'))],
});

/**
 * Apple WebAuthn Root CA PEM
 *
 * Downloaded from https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
 *
 * Valid until 2045-03-14 @ 17:00 PST
 */
settingsService.setRootCertificates({
  attestationFormat: 'apple',
  certificates: [
    fs.readFileSync(path.resolve(__dirname, './defaultRootCerts/Apple_WebAuthn_Root_CA.pem'), {
      encoding: 'utf-8',
    }),
  ],
});

export default settingsService;
