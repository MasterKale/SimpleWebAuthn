import jsrsasign from 'jsrsasign';

import { CertificateInfo } from '@libTypes';

/**
 * Extract PEM certificate info
 *
 * @param pemCertificate Result from call to `convertASN1toPEM(x5c[0])`
 */
export default function getCertificateInfo(pemCertificate: string): CertificateInfo {
  const subjectCert = new jsrsasign.X509();
  subjectCert.readCertPEM(pemCertificate);

  const subjectString = subjectCert.getSubjectString();
  const subjectParts = subjectString.slice(1).split('/');

  const subject: { [key: string]: string } = {};
  subjectParts.forEach((field) => {
    const [key, val] = field.split('=');
    subject[key] = val;
  });

  const { getVersion } = subjectCert;
  const basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

  return {
    subject,
    version: getVersion(),
    basicConstraintsCA,
  };
}
