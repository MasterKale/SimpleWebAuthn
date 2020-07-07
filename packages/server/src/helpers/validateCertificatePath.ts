/* eslint-disable @typescript-eslint/ban-ts-comment */
// ASN1HEX exists in the lib, but not typings, I swear
// @ts-ignore 2305
import { KJUR, X509, ASN1HEX, zulutodate } from 'jsrsasign';
import fetch from 'node-fetch';

import { leafCertToASN1Object, asn1ObjectToJSON, JASN1 } from './asn1Utils';

const { crypto } = KJUR;

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param certificates Typically the result of `x5c.map(convertASN1toPEM)`
 */
export default async function validateCertificatePath(certificates: string[]): Promise<boolean> {
  if (new Set(certificates).size !== certificates.length) {
    throw new Error('Invalid certificate path: found duplicate certificates');
  }

  // From leaf to root, make sure each cert is issued by the next certificate in the chain
  for (let i = 0; i < certificates.length; i += 1) {
    const subjectPem = certificates[i];

    const subjectCert = new X509();
    subjectCert.readCertPEM(subjectPem);

    let issuerPem = '';
    if (i + 1 >= certificates.length) {
      issuerPem = subjectPem;
    } else {
      issuerPem = certificates[i + 1];
    }

    const issuerCert = new X509();
    issuerCert.readCertPEM(issuerPem);

    // Check that intermediate certificate is within its valid time window
    const notBefore = zulutodate(issuerCert.getNotBefore());
    const notAfter = zulutodate(issuerCert.getNotAfter());

    const now = new Date();
    if (notBefore > now || notAfter < now) {
      throw new Error('Intermediate certificate is not yet valid or expired');
    }

    if (subjectCert.getIssuerString() !== issuerCert.getSubjectString()) {
      throw new Error('Invalid certificate path: subject issuer did not match issuer subject');
    }

    const subjectCertStruct = ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
    const alg = subjectCert.getSignatureAlgorithmField();
    const signatureHex = subjectCert.getSignatureValueHex();

    const Signature = new crypto.Signature({ alg });
    Signature.init(issuerPem);
    Signature.updateHex(subjectCertStruct);

    if (!Signature.verify(signatureHex)) {
      throw new Error('Invalid certificate path: invalid signature');
    }
  }

  return true;
}

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
async function isCertRevoked(cert: X509): Promise<boolean> {
  const crlURL = cert.getExtCRLDistributionPointsURI();

  // If no URL is provided then we have nothing to check
  if (!crlURL) {
    return false;
  }

  const certSerialHex = cert.getSerialNumberHex();

  // Check to see if we've got cached info for the cert's CA
  const certAuthKeyID = cert.getExtAuthorityKeyIdentifier();
  if (certAuthKeyID) {
    const cached = cacheRevokedCerts[certAuthKeyID.kid];
    if (cached) {
      console.log(`Found cached info for CA ID ${certAuthKeyID}`, cached);
      const now = new Date();
      // If there's a nextUpdate then make sure we're before it
      if (!cached.nextUpdate || cached.nextUpdate > now) {
        return cached.revokedCerts.indexOf(certSerialHex) >= 0;
      }
    }
  }

  // Download and read the CRL
  const crlCert = new X509();
  try {
    const respCRL = await fetch(crlURL[0]);
    const dataCRL = await respCRL.text();
    crlCert.readCertPEM(dataCRL);
  } catch (err) {
    return false;
  }

  // Start diving into the CRL's ASN.1 data structure
  const crlASN1 = leafCertToASN1Object(Buffer.from(crlCert.hex, 'hex'));
  const crlJSON = asn1ObjectToJSON(crlASN1);

  const root0 = (crlJSON.data as JASN1[])[0];

  if ((root0.data as JASN1[])?.length < 7) {
    // CRL is empty
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
      cacheRevokedCerts[certAuthKeyID.kid] = newCached;
    }
  }

  return false;
}
