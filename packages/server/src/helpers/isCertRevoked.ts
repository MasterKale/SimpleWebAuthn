import { X509 } from 'jsrsasign';
import fetch from 'node-fetch';
import { AsnParser } from '@peculiar/asn1-schema';
import { CertificateList } from '@peculiar/asn1-x509';

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
export default async function isCertRevoked(cert: X509): Promise<boolean> {
  console.log(`Getting cert serial`);
  const certSerialHex = cert.getSerialNumberHex();

  console.log(`Checking certificate revocation for ${cert.getSerialNumberHex()}`);

  // Check to see if we've got cached info for the cert's CA
  console.log(`Getting cert auth key ID`);
  let certAuthKeyID: { kid: string } | null = null;
  try {
    certAuthKeyID = cert.getExtAuthorityKeyIdentifier();
  } catch (err) {
    console.error('error getting auth key id:', err.message);
    return false;
  }

  console.log('cert auth key id:', certAuthKeyID);

  if (certAuthKeyID) {
    const cached = cacheRevokedCerts[certAuthKeyID.kid];
    if (cached) {
      console.log(`Found cached info for CA ID ${certAuthKeyID.kid}`, cached);
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
    console.error(`Error getting cert CDP URIs: ${err.message}`);
    return false;
  }

  // If no URL is provided then we have nothing to check
  if (!crlURL) {
    console.error(`No CDP URIs for certificate`);
    return false;
  }

  // Download and read the CRL
  const crlCert = new X509();
  try {
    console.log(`Download CRL`);
    const respCRL = await fetch(crlURL[0]);
    const dataCRL = await respCRL.text();
    crlCert.readCertPEM(dataCRL);
  } catch (err) {
    console.error(`Error downloading CRL: ${err.message}`);
    return false;
  }

  const data = AsnParser.parse(Buffer.from(crlCert.hex, 'hex'), CertificateList);

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
      const revokedHex = Buffer.from(cert.userCertificate).toString('hex');
      newCached.revokedCerts.push(revokedHex);
    }

    // Cache the results
    if (certAuthKeyID) {
      console.log(`Adding cached info for CA ID ${certAuthKeyID.kid}:`, newCached);
      cacheRevokedCerts[certAuthKeyID.kid] = newCached;
    }

    console.log('checking if this cert is in new list of revoked certs');
    return newCached.revokedCerts.indexOf(certSerialHex) >= 0;
  }

  return false;
}
