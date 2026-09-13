import 'reflect-metadata';
import {
  AuthorityKeyIdentifierExtension,
  CRLDistributionPointsExtension,
  SubjectKeyIdentifierExtension,
  type X509Certificate,
  X509Crl,
} from '@peculiar/x509';

import { fetch } from './fetch.ts';

/**
 * A cache of revoked cert serial numbers by Authority Key ID
 */
type CAAuthorityInfo = {
  // A list of certificates serial numbers in hex format
  revokedCerts: string[];
  // An optional date by which an update should be published
  nextUpdate?: Date;
};
const cacheRevokedCerts: { [issuerKeyIDCRLURLCacheKey: string]: CAAuthorityInfo } = {};

/**
 * A method to pull a CRL from a certificate and compare its serial number to the list of revoked
 * certificate serial numbers within the CRL.
 *
 * CRL certificate structure referenced from https://tools.ietf.org/html/rfc5280#page-117
 */
export async function isCertRevoked(
  certificate: X509Certificate,
  issuer?: X509Certificate,
): Promise<boolean> {
  if (!issuer) {
    // We don't have a public key to verify any CRL signature so don't bother continuing
    return false;
  }

  const { extensions } = certificate;

  if (!extensions) {
    return false;
  }

  const extCRLDistributionPoints = extensions.find(
    (ext) => ext instanceof CRLDistributionPointsExtension,
  );

  // Get all CRL URLs from within the certificate
  const crlURLs: string[] = [];

  extCRLDistributionPoints?.distributionPoints?.forEach((dPoint) => {
    dPoint.distributionPoint?.fullName?.forEach((fullName) => {
      if (fullName.uniformResourceIdentifier) {
        crlURLs.push(fullName.uniformResourceIdentifier);
      }
    });
  });

  // If no URL(s) is provided then we have nothing to check
  if (!(crlURLs.length > 0)) {
    return false;
  }

  // Get the issuer's key identifier for part of the cache key and to check against the
  // certificate's and CRL's AuthorityKeyIdentifier extension
  const {
    keyIdentifier: issuerKeyIdentifier,
    fromExtension: issuerKeyIdentifierFromExtension,
  } = await getIssuerKeyIdentifier(issuer);
  const certificateExtAuthorityKeyID = certificate.extensions.find(
    (ext) => ext instanceof AuthorityKeyIdentifierExtension,
  );

  // When present, assert that certificates's AuthorityKeyIdentifier mirrors
  // the issuer's SubjectKeyIdentifier
  if (
    issuerKeyIdentifierFromExtension &&
    certificateExtAuthorityKeyID?.keyId &&
    certificateExtAuthorityKeyID.keyId !== issuerKeyIdentifier
  ) {
    throw new Error(
      `Certificate's AuthorityKeyIdentifier did not match issuer's SubjectKeyIdentifier "${issuerKeyIdentifier}"`,
    );
  }

  for (const crlURL of crlURLs) {
    // Key off of issuer public key and CRL URL in case multiple CRLs are specified
    const cacheKey = `${issuerKeyIdentifier}|${crlURL}`;

    const cached = cacheRevokedCerts[cacheKey];
    if (cached) {
      const now = new Date();
      // If there's a nextUpdate then make sure we're before it
      if (!cached.nextUpdate || cached.nextUpdate > now) {
        return cached.revokedCerts.indexOf(certificate.serialNumber) >= 0;
      }
    }

    // Download and read the CRL
    let crlBytes: ArrayBuffer;
    try {
      const respCRL = await fetch(crlURL);
      crlBytes = await respCRL.arrayBuffer();
    } catch (_err) {
      // Some kind of network error occurred so try the next URL
      continue;
    }

    let certCRL: X509Crl;
    try {
      certCRL = new X509Crl(crlBytes);
    } catch (_err) {
      // Something was malformed with the CRL so try the next URL
      continue;
    }

    const certCRLVerified = await certCRL.verify({ publicKey: issuer.publicKey });
    if (!certCRLVerified) {
      throw new Error(
        `CRL from ${crlURL} failed signature verification against issuer "${issuer.subject}"`,
      );
    }

    // When present, assert that the CRL's AuthorityKeyIdentifier mirrors
    // the issuer's SubjectKeyIdentifier
    const crlAKI = certCRL.getExtension(AuthorityKeyIdentifierExtension);
    if (
      issuerKeyIdentifierFromExtension &&
      crlAKI?.keyId &&
      crlAKI.keyId !== issuerKeyIdentifier
    ) {
      throw new Error(
        `CRL from ${crlURL} contained an AuthorityKeyIdentifier that did not match issuer's SubjectKeyIdentifier "${issuerKeyIdentifier}"`,
      );
    }

    // Cache the CRL only if a nextUpdate has been provided
    if (certCRL.nextUpdate) {
      cacheRevokedCerts[cacheKey] = {
        revokedCerts: certCRL.entries.map((entry) => entry.serialNumber),
        nextUpdate: certCRL.nextUpdate,
      };
    }

    // Finally, check entries for revocation status
    const revoked = certCRL.findRevoked(certificate);

    if (revoked) {
      return true;
    }
  }

  return false;
}

/**
 * Determine a unique key ID for the issuer certificate, based either on its
 * SubjectKeyIdentifierExtension or by generating the same value using the issuer's public key
 */
async function getIssuerKeyIdentifier(
  issuer: X509Certificate,
): Promise<{ keyIdentifier: string; fromExtension: boolean }> {
  const issuerSKI = issuer.extensions?.find((ext) => ext instanceof SubjectKeyIdentifierExtension);

  if (issuerSKI?.keyId) {
    return { keyIdentifier: issuerSKI.keyId, fromExtension: true };
  }

  /**
   * The issuer carries no SubjectKeyIdentifier extension, so derive one from its public key
   * (RFC 5280, method 1). This is good enough to keep unrelated CAs from colliding when computing
   * the revocation cache key, but it's not authoritative enough to reject a certificate over.
   */
  const computed = await SubjectKeyIdentifierExtension.create(issuer.publicKey);
  return { keyIdentifier: computed.keyId, fromExtension: false };
}
