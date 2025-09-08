import { X509Certificate } from '@peculiar/x509';

import { isCertRevoked } from './isCertRevoked.ts';
import { getWebCrypto } from './iso/isoCrypto/getWebCrypto.ts';

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param x5cCertsPEM Typically the result of `x5c.map(convertASN1toPEM)`
 * @param trustAnchorsPEM PEM-formatted certs that an attestation statement x5c may chain back to
 */
export async function validateCertificatePath(
  x5cCertsPEM: string[],
  trustAnchorsPEM: string[] = [],
): Promise<boolean> {
  if (trustAnchorsPEM.length === 0) {
    // We have no trust anchors to chain back to, so skip path validation
    return true;
  }

  const WebCrypto = await getWebCrypto();

  // Prepare to work with x5c certs
  const x5cCertsParsed = x5cCertsPEM.map((certPEM) => new X509Certificate(certPEM));

  // Check for any expired or temporally invalid certs in x5c
  for (let i = 0; i < x5cCertsParsed.length; i++) {
    const cert = x5cCertsParsed[i];
    const certPEM = x5cCertsPEM[i];

    try {
      await assertCertNotRevoked(cert);
    } catch (_err) {
      throw new Error(`Found revoked certificate in x5c:\n${certPEM}`);
    }

    try {
      assertCertIsWithinValidTimeWindow(cert.notBefore, cert.notAfter);
    } catch (_err) {
      throw new Error(`Found certificate out of validity period in x5c:\n${certPEM}`);
    }
  }

  // Prepare to work with trust anchor certs
  const trustAnchorsParsed = trustAnchorsPEM.map((certPEM) => {
    try {
      return new X509Certificate(certPEM);
    } catch (err) {
      const _err = err as Error;
      throw new Error(`Could not parse trust anchor certificate:\n${certPEM}`, { cause: _err });
    }
  });

  // Filter out any expired or temporally invalid trust anchors certs
  const validTrustAnchors: X509Certificate[] = [];
  for (let i = 0; i < trustAnchorsParsed.length; i++) {
    const cert = trustAnchorsParsed[i];

    try {
      await assertCertNotRevoked(cert);
    } catch (_err) {
      // Continue processing the other certs
      continue;
    }

    try {
      assertCertIsWithinValidTimeWindow(cert.notBefore, cert.notAfter);
    } catch (_err) {
      // Continue processing the other certs
      continue;
    }

    validTrustAnchors.push(cert);
  }

  if (validTrustAnchors.length === 0) {
    throw new Error('No specified trust anchor was valid for verifying x5c');
  }

  // Try to verify x5c with each trust anchor
  let invalidSubjectAndIssuerError = false;
  for (const anchor of trustAnchorsParsed) {
    try {
      const x5cWithTrustAnchor = x5cCertsParsed.concat([anchor]);

      if (new Set(x5cWithTrustAnchor).size !== x5cWithTrustAnchor.length) {
        throw new Error('Invalid certificate path: found duplicate certificates');
      }

      // Check signatures, and notBefore and notAfter
      for (let i = 0; i < x5cWithTrustAnchor.length - 1; i++) {
        const subject = x5cWithTrustAnchor[i];
        const issuer = x5cWithTrustAnchor[i + 1];

        // Leaf or intermediate cert, make sure the next cert in the chain signed it
        const issuerSignedSubject = await subject.verify(
          { publicKey: issuer.publicKey, signatureOnly: true },
          WebCrypto,
        );

        if (!issuerSignedSubject) {
          throw new InvalidSubjectAndIssuer();
        }

        if (issuer.subject === issuer.issuer) {
          // Root cert detected, make sure it signed itself
          const issuerSignedIssuer = await issuer.verify(
            { publicKey: issuer.publicKey, signatureOnly: true },
            WebCrypto,
          );

          if (!issuerSignedIssuer) {
            throw new InvalidSubjectAndIssuer();
          }

          // Don't process anything else after a root cert
          break;
        }
      }

      // If we successfully validated a path then there's no need to continue. Reset any existing
      // errors that were thrown by earlier trust anchors
      invalidSubjectAndIssuerError = false;
      break;
    } catch (err) {
      if (err instanceof InvalidSubjectAndIssuer) {
        invalidSubjectAndIssuerError = true;
      } else {
        throw new Error('Unexpected error while validating certificate path', { cause: err });
      }
    }
  }

  // We tried multiple trust anchors and none of them worked
  if (invalidSubjectAndIssuerError) {
    throw new InvalidSubjectAndIssuer();
  }

  return true;
}

/**
 * Check if the certificate is revoked or not. If it is, raise an error
 */
async function assertCertNotRevoked(certificate: X509Certificate): Promise<void> {
  // Check for certificate revocation
  const subjectCertRevoked = await isCertRevoked(certificate);

  if (subjectCertRevoked) {
    throw new Error('Found revoked certificate in certificate path');
  }
}

/**
 * Require the cert to be within its notBefore and notAfter time window
 */
function assertCertIsWithinValidTimeWindow(certNotBefore: Date, certNotAfter: Date): void {
  const now = new Date(Date.now());
  if (certNotBefore > now || certNotAfter < now) {
    throw new Error('Certificate is not yet valid or expired');
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
