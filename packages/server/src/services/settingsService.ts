import fs from 'fs';
import path from 'path';

import { AttestationFormat } from '../helpers/decodeAttestationObject';
import convertCertBufferToPEM from '../helpers/convertCertBufferToPEM';

class SettingsService {
  // Certificates are stored as PEM-formatted strings
  private pemCertificates: Map<AttestationFormat, string>;

  constructor() {
    this.pemCertificates = new Map();
  }

  /**
   * Allow setting custom root certificates for attestation formats that use them
   *
   * The certificate can be specified as a raw `Buffer`, or as a PEM-formatted string. If a
   * `Buffer` is passed in it will be converted to PEM format.
   */
  setRootCertificate(opts: {
    attestationFormat: AttestationFormat;
    certificate: Buffer | string;
  }): void {
    const { attestationFormat } = opts;
    let { certificate: newCertificate } = opts;

    if (newCertificate instanceof Buffer) {
      newCertificate = convertCertBufferToPEM(newCertificate);
    }

    this.pemCertificates.set(attestationFormat, newCertificate);
  }

  /**
   * Get any registered root certificates for the specified attestation format
   */
  getRootCertificate(opts: { attestationFormat: AttestationFormat }): string {
    const { attestationFormat } = opts;
    return this.pemCertificates.get(attestationFormat) ?? '';
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
settingsService.setRootCertificate({
  attestationFormat: 'android-safetynet',
  certificate: fs.readFileSync(path.resolve(__dirname, './defaultRootCerts/GSR2.crt')),
});

/**
 * Apple WebAuthn Root CA PEM
 *
 * Downloaded from https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
 *
 * Valid until 2045-03-14 @ 17:00 PST
 */
settingsService.setRootCertificate({
  attestationFormat: 'apple',
  certificate: fs.readFileSync(
    path.resolve(__dirname, './defaultRootCerts/Apple_WebAuthn_Root_CA.pem'),
    { encoding: 'utf-8' },
  ),
});

export default settingsService;
