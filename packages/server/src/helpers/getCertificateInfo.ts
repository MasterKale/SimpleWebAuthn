import { X509, zulutodate } from 'jsrsasign';

export type CertificateInfo = {
  issuer: { [key: string]: string };
  subject: { [key: string]: string };
  version: number;
  basicConstraintsCA: boolean;
  notBefore: Date;
  notAfter: Date;
  extendedKeyUsageIDs: string[];
  tpmInfo?: {
    subjectAltNamePresent: boolean;
    tcgAtTpmManufacturer: string;
    tcgAtTpmModel: string;
    tcgAtTpmVersion: string;
    extKeyUsage: string;
  };
};

type ExtInfo = {
  critical: boolean;
  oid: string;
  vidx: number;
};

interface x5cCertificate extends jsrsasign.X509 {
  version: number;
  foffset: number;
  aExtInfo: ExtInfo[];
}

/**
 * Extract PEM certificate info
 *
 * @param pemCertificate Result from call to `convertASN1toPEM(x5c[0])`
 */
export default function getCertificateInfo(pemCertificate: string): CertificateInfo {
  const subjectCert = new X509();
  subjectCert.readCertPEM(pemCertificate);

  // Break apart the Issuer
  const issuerString = subjectCert.getIssuerString();
  const issuerParts = issuerString.slice(1).split('/');

  const issuer: { [key: string]: string } = {};
  issuerParts.forEach(field => {
    const [key, val] = field.split('=');
    issuer[key] = val;
  });

  // Break apart the Subject
  let subjectRaw = '/';
  try {
    subjectRaw = subjectCert.getSubjectString();
  } catch (err) {
    // Don't throw on an error that indicates an empty subject
    if (err !== 'malformed RDN') {
      throw err;
    }
  }
  const subjectParts = subjectRaw.slice(1).split('/');

  const subject: { [key: string]: string } = {};
  subjectParts.forEach(field => {
    if (field) {
      const [key, val] = field.split('=');
      subject[key] = val;
    }
  });

  const { version } = subjectCert as x5cCertificate;
  const basicConstraintsCA = !!subjectCert.getExtBasicConstraints()?.cA;

  const toReturn: CertificateInfo = {
    issuer,
    subject,
    version,
    basicConstraintsCA,
    notBefore: zulutodate(subjectCert.getNotBefore()),
    notAfter: zulutodate(subjectCert.getNotAfter()),
    extendedKeyUsageIDs: subjectCert.getExtExtKeyUsageName() || [],
  };

  return toReturn;
}
