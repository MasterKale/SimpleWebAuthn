import { X509 } from 'jsrsasign';
import fetch from 'cross-fetch';
import { AsnParser } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';

import { convertCertBufferToPEM } from './convertCertBufferToPEM';
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
export async function isCertRevoked(cert: X509): Promise<boolean> {
  const certSerialHex = cert.getSerialNumberHex();

  // Check to see if we've got cached info for the cert's CA
  let certAuthKeyID: { kid: { hex: string } } | null = null;
  try {
    certAuthKeyID = cert.getExtAuthorityKeyIdentifier() as { kid: { hex: string } } | null;
  } catch (err) {
    return false;
  }

  if (certAuthKeyID) {
    const cached = cacheRevokedCerts[certAuthKeyID.kid.hex];
    if (cached) {
      const now = new Date();
      // If there's a nextUpdate then make sure we're before it
      if (!cached.nextUpdate || cached.nextUpdate > now) {
        return cached.revokedCerts.indexOf(certSerialHex) >= 0;
      }
    }
  }

  let crlURL = undefined;
  try {
    crlURL = cert.getExtCRLDistributionPointsURI();
  } catch (err) {
    // Cert probably didn't include any CDP URIs
    return false;
  }

  // If no URL is provided then we have nothing to check
  if (!crlURL) {
    return false;
  }

  // Download and read the CRL
  const crlCert = new X509();
  try {
    const respCRL = await fetch(crlURL[0]);
    const dataCRL = await respCRL.arrayBuffer();
    const dataPEM = convertCertBufferToPEM(new Uint8Array(dataCRL));
    crlCert.readCertPEM(dataPEM);
  } catch (err) {
    return false;
  }

  const data = AsnParser.parse(isoUint8Array.fromHex(crlCert.hex), CertificateList);

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
    if (certAuthKeyID) {
      cacheRevokedCerts[certAuthKeyID.kid.hex] = newCached;
    }

    return newCached.revokedCerts.indexOf(certSerialHex) >= 0;
  }

  return false;
}
