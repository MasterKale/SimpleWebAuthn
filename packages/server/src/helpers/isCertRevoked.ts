import { X509 } from 'jsrsasign';
import fetch from 'node-fetch';

import { leafCertToASN1Object, asn1ObjectToJSON, JASN1 } from './asn1Utils';

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
    console.error(`Download CRL`);
    const respCRL = await fetch(crlURL[0]);
    const dataCRL = await respCRL.text();
    crlCert.readCertPEM(dataCRL);
  } catch (err) {
    console.error(`Error downloading CRL: ${err.message}`);
    return false;
  }

  // Start diving into the CRL's ASN.1 data structure
  const crlASN1 = leafCertToASN1Object(Buffer.from(crlCert.hex, 'hex'));
  const crlJSON = asn1ObjectToJSON(crlASN1);

  const root0 = (crlJSON.data as JASN1[])[0];

  if ((root0.data as JASN1[])?.length < 7) {
    // CRL is empty
    console.log('CRL is empty');
    return false;
  }

  const newCached: CAAuthorityInfo = {
    revokedCerts: [],
    nextUpdate: undefined,
  };

  // nextUpdate
  const root04 = (root0.data as JASN1[])[4];
  if (root04) {
    console.log('nextUpdate:', root04.data);
    newCached.nextUpdate = new Date(root04.data as string);
  }

  // revokedCertificates
  const root05 = (root0.data as JASN1[])[5];
  const revokedCerts = root05.data;

  if (revokedCerts) {
    for (const cert of revokedCerts) {
      const certSerialData = (cert as JASN1).data;
      if (certSerialData) {
        const certSerialSequence = (certSerialData[0] as JASN1).data;
        if (typeof certSerialSequence === 'string') {
          // Grab the value after "\n" in "(115 bit)\n23373519225161898650309958210680307"
          const revokedHex = parseInt(certSerialSequence.split('\n')[1], 10).toString(16);
          // Push the revoked cert serial hex into the cache
          newCached.revokedCerts.push(revokedHex);

          // Check to see if this cert is one of the revoked certificates
          console.log(`Checking if cert ${certSerialHex} matches revoked ${revokedHex}`);
          if (certSerialHex === revokedHex) {
            return true;
          }
        }
      }
    }

    // Cache the results
    if (certAuthKeyID) {
      console.log(`Adding cached info for CA ID ${certAuthKeyID.kid}:`, newCached);
      cacheRevokedCerts[certAuthKeyID.kid] = newCached;
    }
  }

  return false;
}
