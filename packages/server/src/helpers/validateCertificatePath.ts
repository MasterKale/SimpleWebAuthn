/* eslint-disable @typescript-eslint/ban-ts-comment */
import { AsnSerializer } from '@peculiar/asn1-schema';

import { isCertRevoked } from './isCertRevoked';
import { verifySignature } from './verifySignature';
import { mapX509SignatureAlgToCOSEAlg } from './mapX509SignatureAlgToCOSEAlg';
import { getCertificateInfo } from './getCertificateInfo';
import { convertPEMToBytes } from './convertPEMToBytes';

/**
 * Traverse an array of PEM certificates and ensure they form a proper chain
 * @param certificates Typically the result of `x5c.map(convertASN1toPEM)`
 * @param rootCertificates Possible root certificates to complete the path
 */
export async function validateCertificatePath(
  certificates: string[],
  rootCertificates: string[] = [],
): Promise<boolean> {
  if (rootCertificates.length === 0) {
    // We have no root certs with which to create a full path, so skip path validation
    // TODO: Is this going to be acceptable default behavior??
    return true;
  }

  let invalidSubjectAndIssuerError = false;
  let certificateNotYetValidOrExpiredErrorMessage = undefined;
  for (const rootCert of rootCertificates) {
    try {
      const certsWithRoot = certificates.concat([rootCert]);
      await _validatePath(certsWithRoot);
      // If we successfully validated a path then there's no need to continue. Reset any existing
      // errors that were thrown by earlier root certificates
      invalidSubjectAndIssuerError = false;
      certificateNotYetValidOrExpiredErrorMessage = undefined;
      break;
    } catch (err) {
      if (err instanceof InvalidSubjectAndIssuer) {
        invalidSubjectAndIssuerError = true;
      } else if (err instanceof CertificateNotYetValidOrExpired) {
        certificateNotYetValidOrExpiredErrorMessage = err.message;
      } else {
        throw err;
      }
    }
  }

  // We tried multiple root certs and none of them worked
  if (invalidSubjectAndIssuerError) {
    throw new InvalidSubjectAndIssuer();
  } else if (certificateNotYetValidOrExpiredErrorMessage) {
    throw new CertificateNotYetValidOrExpired(certificateNotYetValidOrExpiredErrorMessage);
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

    const isLeafCert = i === 0;
    const isRootCert = i + 1 >= certificates.length;

    let issuerPem = '';
    if (isRootCert) {
      issuerPem = subjectPem;
    } else {
      issuerPem = certificates[i + 1];
    }

    const subjectInfo = getCertificateInfo(convertPEMToBytes(subjectPem));
    const issuerInfo = getCertificateInfo(convertPEMToBytes(issuerPem));

    const x509Subject = subjectInfo.parsedCertificate;

    // Check for certificate revocation
    const subjectCertRevoked = await isCertRevoked(x509Subject);

    if (subjectCertRevoked) {
      throw new Error(`Found revoked certificate in certificate path`);
    }

    // Check that intermediate certificate is within its valid time window
    const { notBefore, notAfter } = issuerInfo;

    const now = new Date(Date.now());
    if (notBefore > now || notAfter < now) {
      if (isLeafCert) {
        throw new CertificateNotYetValidOrExpired(
          `Leaf certificate is not yet valid or expired: ${issuerPem}`,
        );
      } else if (isRootCert) {
        throw new CertificateNotYetValidOrExpired(
          `Root certificate is not yet valid or expired: ${issuerPem}`,
        );
      } else {
        throw new CertificateNotYetValidOrExpired(
          `Intermediate certificate is not yet valid or expired: ${issuerPem}`,
        );
      }
    }

    if (subjectInfo.issuer.combined !== issuerInfo.subject.combined) {
      throw new InvalidSubjectAndIssuer();
    }

    // Verify the subject certificate's signature with the issuer cert's public key
    const data = AsnSerializer.serialize(x509Subject.tbsCertificate);
    const signature = x509Subject.signatureValue;
    const signatureAlgorithm = mapX509SignatureAlgToCOSEAlg(
      x509Subject.signatureAlgorithm.algorithm,
    );
    const issuerCertBytes = convertPEMToBytes(issuerPem);

    const verified = await verifySignature({
      data: new Uint8Array(data),
      signature: new Uint8Array(signature),
      x509Certificate: issuerCertBytes,
      hashAlgorithm: signatureAlgorithm,
    });

    if (!verified) {
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

class CertificateNotYetValidOrExpired extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CertificateNotYetValidOrExpired';
  }
}
