import { AsnSerializer } from '@peculiar/asn1-schema';
import type { Certificate } from '@peculiar/asn1-x509';

import { isCertRevoked } from './isCertRevoked.ts';
import { verifySignature } from './verifySignature.ts';
import { mapX509SignatureAlgToCOSEAlg } from './mapX509SignatureAlgToCOSEAlg.ts';
import { type CertificateInfo, getCertificateInfo } from './getCertificateInfo.ts';
import { convertPEMToBytes } from './convertPEMToBytes.ts';

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param x5cPEMCerts Typically the result of `x5c.map(convertASN1toPEM)`
 * @param trustAnchors Certificates that an attestation statement x5c may chain back to
 */
export async function validateCertificatePath(
  x5cPEMCerts: string[],
  trustAnchors: string[] = [],
): Promise<boolean> {
  if (trustAnchors.length === 0) {
    // We have no trust anchors to chain back to, so skip path validation
    return true;
  }

  let invalidSubjectAndIssuerError = false;
  let certificateNotYetValidOrExpiredErrorMessage = undefined;
  for (const anchor of trustAnchors) {
    try {
      const certsWithTrustAnchor = x5cPEMCerts.concat([anchor]);
      await _validatePath(certsWithTrustAnchor);
      // If we successfully validated a path then there's no need to continue. Reset any existing
      // errors that were thrown by earlier trust anchors
      invalidSubjectAndIssuerError = false;
      certificateNotYetValidOrExpiredErrorMessage = undefined;
      break;
    } catch (err) {
      if (err instanceof InvalidSubjectAndIssuer) {
        invalidSubjectAndIssuerError = true;
      } else if (err instanceof CertificateNotYetValidOrExpired) {
        certificateNotYetValidOrExpiredErrorMessage = err.message;
      } else {
        throw err;
      }
    }
  }

  // We tried multiple trust anchors and none of them worked
  if (invalidSubjectAndIssuerError) {
    throw new InvalidSubjectAndIssuer();
  } else if (certificateNotYetValidOrExpiredErrorMessage) {
    throw new CertificateNotYetValidOrExpired(
      certificateNotYetValidOrExpiredErrorMessage,
    );
  }

  return true;
}

/**
 * @param x5cCerts X.509 `x5c` certs in PEM string format
 * @param anchorCert X.509 trust anchor cert in PEM string format
 */
async function _validatePath(x5cCertsWithTrustAnchor: string[]): Promise<boolean> {
  if (new Set(x5cCertsWithTrustAnchor).size !== x5cCertsWithTrustAnchor.length) {
    throw new Error('Invalid certificate path: found duplicate certificates');
  }

  // Make sure no certs are revoked, and all are within their time validity window
  for (const certificate of x5cCertsWithTrustAnchor) {
    const certInfo = getCertificateInfo(convertPEMToBytes(certificate));
    await assertCertNotRevoked(certInfo.parsedCertificate);
    assertCertIsWithinValidTimeWindow(certInfo, certificate);
  }

  // Make sure each x5c cert is issued by the next certificate in the chain
  for (let i = 0; i < (x5cCertsWithTrustAnchor.length - 1); i += 1) {
    const subjectPem = x5cCertsWithTrustAnchor[i];
    const issuerPem = x5cCertsWithTrustAnchor[i + 1];

    const subjectInfo = getCertificateInfo(convertPEMToBytes(subjectPem));
    const issuerInfo = getCertificateInfo(convertPEMToBytes(issuerPem));

    // Make sure subject issuer is issuer subject
    if (subjectInfo.issuer.combined !== issuerInfo.subject.combined) {
      throw new InvalidSubjectAndIssuer();
    }

    const issuerCertIsRootCert = issuerInfo.issuer.combined === issuerInfo.subject.combined;

    await assertSubjectIsSignedByIssuer(subjectInfo.parsedCertificate, issuerPem);

    // Perform one final check if the issuer cert is also a root certificate
    if (issuerCertIsRootCert) {
      await assertSubjectIsSignedByIssuer(issuerInfo.parsedCertificate, issuerPem);
    }
  }

  return true;
}

/**
 * Check if the certificate is revoked or not. If it is, raise an error
 */
async function assertCertNotRevoked(certificate: Certificate): Promise<void> {
  // Check for certificate revocation
  const subjectCertRevoked = await isCertRevoked(certificate);

  if (subjectCertRevoked) {
    throw new Error(`Found revoked certificate in certificate path`);
  }
}

/**
 * Require the cert to be within its notBefore and notAfter time window
 *
 * @param certInfo Parsed cert information
 * @param certPEM PEM-formatted certificate, for error reporting
 */
function assertCertIsWithinValidTimeWindow(certInfo: CertificateInfo, certPEM: string): void {
  const { notBefore, notAfter } = certInfo;

  const now = new Date(Date.now());
  if (notBefore > now || notAfter < now) {
    throw new CertificateNotYetValidOrExpired(
      `Certificate is not yet valid or expired: ${certPEM}`,
    );
  }
}

/**
 * Ensure that the subject cert has been signed by the next cert in the chain
 */
async function assertSubjectIsSignedByIssuer(
  subjectCert: Certificate,
  issuerPEM: string,
): Promise<void> {
  // Verify the subject certificate's signature with the issuer cert's public key
  const data = AsnSerializer.serialize(subjectCert.tbsCertificate);
  const signature = subjectCert.signatureValue;
  const signatureAlgorithm = mapX509SignatureAlgToCOSEAlg(
    subjectCert.signatureAlgorithm.algorithm,
  );
  const issuerCertBytes = convertPEMToBytes(issuerPEM);

  const verified = await verifySignature({
    data: new Uint8Array(data),
    signature: new Uint8Array(signature),
    x509Certificate: issuerCertBytes,
    hashAlgorithm: signatureAlgorithm,
  });

  if (!verified) {
    throw new InvalidSubjectSignatureForIssuer();
  }
}

// Custom errors to help pass on certain errors
class InvalidSubjectAndIssuer extends Error {
  constructor() {
    const message = 'Subject issuer did not match issuer subject';
    super(message);
    this.name = 'InvalidSubjectAndIssuer';
  }
}

class InvalidSubjectSignatureForIssuer extends Error {
  constructor() {
    const message = 'Subject signature was invalid for issuer';
    super(message);
    this.name = 'InvalidSubjectSignatureForIssuer';
  }
}

class CertificateNotYetValidOrExpired extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateNotYetValidOrExpired';
  }
}
