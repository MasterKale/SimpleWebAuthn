import { AttestationFormat } from '../helpers/decodeAttestationObject';
import convertCertBufferToPEM from '../helpers/convertCertBufferToPEM';

import GlobalSign_Root_CA from './defaultRootCerts/GlobalSign_Root_CA';
import GlobalSign_R2 from './defaultRootCerts/GlobalSign_R2';
import Apple_WebAuthn_Root_CA from './defaultRootCerts/Apple_WebAuthn_Root_CA';

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
settingsService.setRootCertificates({
  attestationFormat: 'android-safetynet',
  certificates: [GlobalSign_R2, GlobalSign_Root_CA],
});

settingsService.setRootCertificates({
  attestationFormat: 'apple',
  certificates: [Apple_WebAuthn_Root_CA],
});

export default settingsService;
