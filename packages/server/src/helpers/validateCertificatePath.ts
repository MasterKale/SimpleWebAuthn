/* eslint-disable @typescript-eslint/ban-ts-comment */
// `ASN1HEX` exists in the lib but not in its typings
// @ts-ignore 2305
import { KJUR, X509, ASN1HEX, zulutodate } from 'jsrsasign';

import isCertRevoked from './isCertRevoked';

const { crypto } = KJUR;

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param certificates Typically the result of `x5c.map(convertASN1toPEM)`
 * @param rootCertificates Possible root certificates to complete the path
 */
export default async function validateCertificatePath(
  certificates: string[],
  rootCertificates: string[] = [],
): Promise<boolean> {
  if (rootCertificates.length === 0) {
    // We have no root certs with which to create a full path, so skip path validation
    // TODO: Is this going to be acceptable default behavior??
    return true;
  }

  let invalidSubjectAndIssuerError = false;
  for (const rootCert of rootCertificates) {
    try {
      const certsWithRoot = certificates.concat([rootCert]);
      await _validatePath(certsWithRoot);
      // If we successfully validated a path then there's no need to continue
      invalidSubjectAndIssuerError = false;
      break;
    } catch (err) {
      if (err instanceof InvalidSubjectAndIssuer) {
        invalidSubjectAndIssuerError = true;
      } else {
        throw err;
      }
    }
  }

  // We tried multiple root certs and none of them worked
  if (invalidSubjectAndIssuerError) {
    throw new InvalidSubjectAndIssuer();
  }

  return true;
}

async function _validatePath(certificates: string[]): Promise<boolean> {
  if (new Set(certificates).size !== certificates.length) {
    throw new Error('Invalid certificate path: found duplicate certificates');
  }

  // From leaf to root, make sure each cert is issued by the next certificate in the chain
  for (let i = 0; i < certificates.length; i += 1) {
    const subjectPem = certificates[i];

    const subjectCert = new X509();
    subjectCert.readCertPEM(subjectPem);

    const isLeafCert = i === 0;
    const isRootCert = i + 1 >= certificates.length;

    let issuerPem = '';
    if (isRootCert) {
      issuerPem = subjectPem;
    } else {
      issuerPem = certificates[i + 1];
    }

    const issuerCert = new X509();
    issuerCert.readCertPEM(issuerPem);

    // Check for certificate revocation
    const subjectCertRevoked = await isCertRevoked(subjectCert);

    if (subjectCertRevoked) {
      throw new Error(`Found revoked certificate in certificate path`);
    }

    // Check that intermediate certificate is within its valid time window
    const notBefore = zulutodate(issuerCert.getNotBefore());
    const notAfter = zulutodate(issuerCert.getNotAfter());

    const now = new Date(Date.now());
    if (notBefore > now || notAfter < now) {
      if (isLeafCert) {
        throw new Error('Leaf certificate is not yet valid or expired');
      } else if (isRootCert) {
        throw new Error('Root certificate is not yet valid or expired');
      } else {
        throw new Error(`Intermediate certificate at index ${i} is not yet valid or expired`);
      }
    }

    if (subjectCert.getIssuerString() !== issuerCert.getSubjectString()) {
      throw new InvalidSubjectAndIssuer();
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

// Custom errors to help pass on certain errors
class InvalidSubjectAndIssuer extends Error {
  constructor() {
    const message = 'Subject issuer did not match issuer subject';
    super(message);
    this.name = 'InvalidSubjectAndIssuer';
  }
}
