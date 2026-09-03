import 'reflect-metadata';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';

import { isCertRevoked } from './isCertRevoked.ts';

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

  // Try to verify x5c with each valid trust anchor
  let invalidCertificateChain = true;
  for (const anchor of validTrustAnchors) {
    try {
      const x5cWithTrustAnchor = x5cCertsParsed.concat([anchor]);
      const numUniqueCerts = new Set(x5cWithTrustAnchor.map((cert) => cert.toString('pem'))).size;

      if (numUniqueCerts !== x5cWithTrustAnchor.length) {
        throw new Error('Invalid certificate path: found duplicate certificates');
      }

      // Break apart x5c to try and build a valid cert chain
      const x5cLeafCert = x5cCertsParsed[0];
      let x5cIntermediates: X509Certificate[] = [];
      if (x5cCertsParsed.length > 1) {
        x5cIntermediates = x5cCertsParsed.slice(1);
      }

      // Order of certs doesn't matter here but for readability
      const chainBuilder = new X509ChainBuilder({ certificates: [...x5cIntermediates, anchor] });
      // Attempt to build a certificate path
      const chain = await chainBuilder.build(x5cLeafCert);

      /**
       * The cert chain must chain to the anchor. Usually this is as simple as asserting that the
       * final cert in the chain is the anchor cert. However there's an odd scenario where an
       * intermediate certificate can chain to an anchor cert's public key, but not actually to the
       * anchor cert because e.g. the chain builder stopped at a cross-signed cert for the anchor
       * and not the anchor cert itself.
       *
       * So here we're going to check for that. In the simplest case we'll be fine with the last
       * cert in the chain being byte-equivalent to the current anchor cert. If not, then move a
       * cert up the chain and explicitly check that it was signed by the anchor cert. This also
       * future-proofs this logic from the internals of whatever future X.509 library might be used
       * to build the cert path.
       */
      const lastCert = chain[chain.length - 1];
      const lastCertEqualsAnchor: boolean = lastCert.equal(anchor);

      let certBeforeLastSignedByAnchor = false;
      if (!lastCertEqualsAnchor && chain.length > 1) {
        const certBeforeLast = chain[chain.length - 2];
        certBeforeLastSignedByAnchor = await certBeforeLast.verify({
          publicKey: anchor.publicKey,
          signatureOnly: true,
        });
      }

      const chainReachesAnchor = lastCertEqualsAnchor || certBeforeLastSignedByAnchor;

      if (!chainReachesAnchor) {
        // Invalid cert chain, try the next trust anchor
        continue;
      }

      // If we successfully validated a path then there's no need to continue. Reset any existing
      // errors that were thrown by earlier trust anchors
      invalidCertificateChain = false;
      break;
    } catch (err) {
      throw new Error('Unexpected error while validating certificate path', { cause: err });
    }
  }

  // We tried multiple trust anchors and none of them worked
  if (invalidCertificateChain) {
    throw new InvalidCertificatePath();
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

class InvalidCertificatePath extends Error {
  constructor() {
    const message = 'x5c could not be chained to any specified trust anchor';
    super(message);
    this.name = 'InvalidX5CChain';
  }
}
