import fetch from 'cross-fetch';
import { AsnParser } from '@peculiar/asn1-schema';
import {
  CertificateList,
  Certificate,
  AuthorityKeyIdentifier,
  id_ce_authorityKeyIdentifier,
  SubjectKeyIdentifier,
  id_ce_subjectKeyIdentifier,
  id_ce_cRLDistributionPoints,
  CRLDistributionPoints,
} from '@peculiar/asn1-x509';

import { isoUint8Array } from './iso';

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
export async function isCertRevoked(cert: Certificate): Promise<boolean> {
  const { extensions } = cert.tbsCertificate;

  if (!extensions) {
    return false;
  }

  let extAuthorityKeyID: AuthorityKeyIdentifier | undefined;
  let extSubjectKeyID: SubjectKeyIdentifier | undefined;
  let extCRLDistributionPoints: CRLDistributionPoints | undefined;

  extensions.forEach(ext => {
    if (ext.extnID === id_ce_authorityKeyIdentifier) {
      extAuthorityKeyID = AsnParser.parse(ext.extnValue, AuthorityKeyIdentifier);
    } else if (ext.extnID === id_ce_subjectKeyIdentifier) {
      extSubjectKeyID = AsnParser.parse(ext.extnValue, SubjectKeyIdentifier);
    } else if (ext.extnID === id_ce_cRLDistributionPoints) {
      extCRLDistributionPoints = AsnParser.parse(ext.extnValue, CRLDistributionPoints);
    }
  });

  // Check to see if we've got cached info for the cert's CA
  let keyIdentifier: string | undefined = undefined;

  if (extAuthorityKeyID && extAuthorityKeyID.keyIdentifier) {
    keyIdentifier = isoUint8Array.toHex(new Uint8Array(extAuthorityKeyID.keyIdentifier.buffer));
  } else if (extSubjectKeyID) {
    /**
     * We might be dealing with a self-signed root certificate. Check the
     * Subject key Identifier extension next.
     */
    keyIdentifier = isoUint8Array.toHex(new Uint8Array(extSubjectKeyID.buffer));
  }

  const certSerialHex = isoUint8Array.toHex(new Uint8Array(cert.tbsCertificate.serialNumber));

  if (keyIdentifier) {
    const cached = cacheRevokedCerts[keyIdentifier];
    if (cached) {
      const now = new Date();
      // If there's a nextUpdate then make sure we're before it
      if (!cached.nextUpdate || cached.nextUpdate > now) {
        return cached.revokedCerts.indexOf(certSerialHex) >= 0;
      }
    }
  }

  const crlURL =
    extCRLDistributionPoints?.[0].distributionPoint?.fullName?.[0].uniformResourceIdentifier;

  // If no URL is provided then we have nothing to check
  if (!crlURL) {
    return false;
  }

  // Download and read the CRL
  let certListBytes: ArrayBuffer;
  try {
    const respCRL = await fetch(crlURL);
    certListBytes = await respCRL.arrayBuffer();
  } catch (err) {
    return false;
  }

  let data: CertificateList;
  try {
    data = AsnParser.parse(certListBytes, CertificateList);
  } catch (err) {
    // Something was malformed with the CRL, so pass
    return false;
  }

  const newCached: CAAuthorityInfo = {
    revokedCerts: [],
    nextUpdate: undefined,
  };

  // nextUpdate
  if (data.tbsCertList.nextUpdate) {
    newCached.nextUpdate = data.tbsCertList.nextUpdate.getTime();
  }

  // revokedCertificates
  const revokedCerts = data.tbsCertList.revokedCertificates;

  if (revokedCerts) {
    for (const cert of revokedCerts) {
      const revokedHex = isoUint8Array.toHex(new Uint8Array(cert.userCertificate));
      newCached.revokedCerts.push(revokedHex);
    }

    // Cache the results
    if (keyIdentifier) {
      cacheRevokedCerts[keyIdentifier] = newCached;
    }

    return newCached.revokedCerts.indexOf(certSerialHex) >= 0;
  }

  return false;
}
