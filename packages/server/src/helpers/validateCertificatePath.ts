import 'reflect-metadata';
import { X509Certificate, type X509Certificates, X509ChainBuilder } from '@peculiar/x509';

import { isCertRevoked } from './isCertRevoked.ts';
import { SimpleWebAuthnError } from '../errors/index.ts';

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

  // Prepare to work with trust anchor certs
  const trustAnchorsParsed = trustAnchorsPEM.map((certPEM) => {
    try {
      return new X509Certificate(certPEM);
    } catch (err) {
      throw new SimpleWebAuthnError({
        message: `Could not parse trust anchor certificate:\n${certPEM}`,
        code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
        cause: err as Error,
      });
    }
  });

  // Filter out any temporally invalid trust anchors certs
  const validTrustAnchors: X509Certificate[] = [];
  for (let i = 0; i < trustAnchorsParsed.length; i++) {
    const cert = trustAnchorsParsed[i];

    try {
      assertCertIsWithinValidTimeWindow(cert);
    } catch (_err) {
      // Continue processing the other certs
      continue;
    }

    validTrustAnchors.push(cert);
  }

  if (validTrustAnchors.length === 0) {
    throw new SimpleWebAuthnError({
      message: 'No specified trust anchor was valid for verifying x5c',
      code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
    });
  }

  // Prepare to work with x5c certs
  const x5cCertsParsed = x5cCertsPEM.map((certPEM) => new X509Certificate(certPEM));

  // Break apart x5c into leaf + intermediates
  const x5cLeafCert = x5cCertsParsed[0];
  let x5cIntermediates: X509Certificate[] = [];
  if (x5cCertsParsed.length > 1) {
    x5cIntermediates = x5cCertsParsed.slice(1);
  }

  // Try to verify x5c with each valid trust anchor
  let invalidCertificateChain = true;
  let validatedChain: X509Certificates | undefined = undefined;
  for (const anchor of validTrustAnchors) {
    try {
      const x5cWithTrustAnchor = x5cCertsParsed.concat([anchor]);
      const numUniqueCerts = new Set(x5cWithTrustAnchor.map((cert) => cert.toString('pem'))).size;

      if (numUniqueCerts !== x5cWithTrustAnchor.length) {
        throw new SimpleWebAuthnError({
          message: 'Invalid certificate path: found duplicate certificates',
          code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
        });
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

      if (certBeforeLastSignedByAnchor) {
        /**
         * Swap out the last cert in the chain with the anchor that we've already verified
         * chains to the second-to-last certificate. This makes it easier to verify the chain
         * as a standard certificate chain.
         */
        chain[chain.length - 1] = anchor;
      }

      // We successfully validated a chain so there's no need to continue
      invalidCertificateChain = false;
      validatedChain = chain;
      break;
    } catch (err) {
      throw new SimpleWebAuthnError({
        message: 'Unexpected error while validating certificate path',
        code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
        cause: err as Error,
      });
    }
  }

  if (validatedChain) {
    // Check for any temporally invalid or expired certs in the chain
    for (let i = 0; i < validatedChain.length; i++) {
      const cert = validatedChain[i];

      try {
        assertCertIsWithinValidTimeWindow(cert);
      } catch (_err) {
        throw new SimpleWebAuthnError({
          message: `Found certificate out of validity period:\n${cert.toString()}`,
          code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
        });
      }

      /**
       * Checking revocation is very expensive so do it only at the end when we're certain a cert
       * is otherwise valid
       */
      let issuerCert: X509Certificate | undefined = undefined;
      if (i < validatedChain.length - 1) {
        // Issuer cert is simply the next cert in the chain
        issuerCert = validatedChain[i + 1];
      } else {
        // `cert` is the anchor. Only try to verify its revocation status if it's a root certificate
        if (await cert.isSelfSigned()) {
          issuerCert = cert;
        }
      }

      try {
        await assertCertNotRevoked(cert, issuerCert);
      } catch (err) {
        throw new SimpleWebAuthnError({
          message: `The following certificate failed revocation status check\n${cert.toString()}`,
          code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
          cause: err as Error,
        });
      }
    }
  } else {
    invalidCertificateChain = true;
  }

  // We tried multiple trust anchors and none of them worked
  if (invalidCertificateChain) {
    throw new SimpleWebAuthnError({
      message: 'x5c could not be chained to any specified trust anchor',
      code: 'CERTIFICATE_PATH_VERIFICATION_FAILED',
    });
  }

  return true;
}

/**
 * Check if the certificate is revoked or not. If it is, raise an error
 *
 * @throws Error - Wrap this in a SimpleWebAuthnError so RPs can identify issues here
 */
async function assertCertNotRevoked(
  certificate: X509Certificate,
  issuerCert?: X509Certificate,
): Promise<void> {
  // Check for certificate revocation
  const subjectCertRevoked = await isCertRevoked(certificate, issuerCert);

  if (subjectCertRevoked) {
    throw new Error('Found revoked certificate in certificate path');
  }
}

/**
 * Require the cert to be within its notBefore and notAfter time window
 */
function assertCertIsWithinValidTimeWindow(certificate: X509Certificate): void {
  const { notBefore: certNotBefore, notAfter: certNotAfter } = certificate;
  const now = new Date(Date.now());
  if (certNotBefore > now || certNotAfter < now) {
    throw new Error('Certificate is not yet valid or expired');
  }
}
