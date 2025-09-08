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
const cacheRevokedCerts: { [certAuthorityKeyID: string]: CAAuthorityInfo } = {};

/**
 * A method to pull a CRL from a certificate and compare its serial number to the list of revoked
 * certificate serial numbers within the CRL.
 *
 * CRL certificate structure referenced from https://tools.ietf.org/html/rfc5280#page-117
 */
export async function isCertRevoked(cert: X509Certificate): Promise<boolean> {
  const { extensions } = cert;

  if (!extensions) {
    return false;
  }

  let extAuthorityKeyID: AuthorityKeyIdentifierExtension | undefined;
  let extSubjectKeyID: SubjectKeyIdentifierExtension | undefined;
  let extCRLDistributionPoints: CRLDistributionPointsExtension | undefined;

  extensions.forEach((ext) => {
    if (ext instanceof AuthorityKeyIdentifierExtension) {
      extAuthorityKeyID = ext;
    } else if (ext instanceof SubjectKeyIdentifierExtension) {
      extSubjectKeyID = ext;
    } else if (ext instanceof CRLDistributionPointsExtension) {
      extCRLDistributionPoints = ext;
    }
  });

  // Check to see if we've got cached info for the cert's CA
  let keyIdentifier: string | undefined = undefined;

  if (extAuthorityKeyID && extAuthorityKeyID.keyId) {
    keyIdentifier = extAuthorityKeyID.keyId;
  } else if (extSubjectKeyID) {
    /**
     * We might be dealing with a self-signed root certificate. Check the
     * Subject key Identifier extension next.
     */
    keyIdentifier = extSubjectKeyID.keyId;
  }

  if (keyIdentifier) {
    const cached = cacheRevokedCerts[keyIdentifier];
    if (cached) {
      const now = new Date();
      // If there's a nextUpdate then make sure we're before it
      if (!cached.nextUpdate || cached.nextUpdate > now) {
        return cached.revokedCerts.indexOf(cert.serialNumber) >= 0;
      }
    }
  }

  const crlURL = extCRLDistributionPoints?.distributionPoints?.[0].distributionPoint?.fullName?.[0]
    .uniformResourceIdentifier;

  // If no URL is provided then we have nothing to check
  if (!crlURL) {
    return false;
  }

  // Download and read the CRL
  let certListBytes: ArrayBuffer;
  try {
    const respCRL = await fetch(crlURL);
    certListBytes = await respCRL.arrayBuffer();
  } catch (_err) {
    return false;
  }

  let data: X509Crl;
  try {
    data = new X509Crl(certListBytes);
  } catch (_err) {
    // Something was malformed with the CRL, so pass
    return false;
  }

  const newCached: CAAuthorityInfo = {
    revokedCerts: [],
    nextUpdate: undefined,
  };

  // nextUpdate
  if (data.nextUpdate) {
    newCached.nextUpdate = data.nextUpdate;
  }

  // revokedCertificates
  const revokedCerts = data.entries;

  if (revokedCerts) {
    for (const cert of revokedCerts) {
      const revokedHex = cert.serialNumber;
      newCached.revokedCerts.push(revokedHex);
    }

    // Cache the results
    if (keyIdentifier) {
      cacheRevokedCerts[keyIdentifier] = newCached;
    }

    return newCached.revokedCerts.indexOf(cert.serialNumber) >= 0;
  }

  return false;
}
