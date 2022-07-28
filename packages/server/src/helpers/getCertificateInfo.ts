import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate, BasicConstraints, id_ce_basicConstraints } from '@peculiar/asn1-x509';

export type CertificateInfo = {
  issuer: Issuer;
  subject: Subject;
  version: number;
  basicConstraintsCA: boolean;
  notBefore: Date;
  notAfter: Date;
};

type Issuer = {
  C?: string;
  O?: string;
  OU?: string;
  CN?: string;
};

type Subject = {
  C?: string;
  O?: string;
  OU?: string;
  CN?: string;
};

const issuerSubjectIDKey: { [key: string]: 'C' | 'O' | 'OU' | 'CN' } = {
  '2.5.4.6': 'C',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.3': 'CN',
};

/**
 * Extract PEM certificate info
 *
 * @param pemCertificate Result from call to `convertASN1toPEM(x5c[0])`
 */
export function getCertificateInfo(leafCertBuffer: Buffer): CertificateInfo {
  const asnx509 = AsnParser.parse(leafCertBuffer, Certificate);
  const parsedCert = asnx509.tbsCertificate;

  // Issuer
  const issuer: Issuer = {};
  parsedCert.issuer.forEach(([iss]) => {
    const key = issuerSubjectIDKey[iss.type];
    if (key) {
      issuer[key] = iss.value.toString();
    }
  });

  // Subject
  const subject: Subject = {};
  parsedCert.subject.forEach(([iss]) => {
    const key = issuerSubjectIDKey[iss.type];
    if (key) {
      subject[key] = iss.value.toString();
    }
  });

  let basicConstraintsCA = false;
  if (parsedCert.extensions) {
    // console.log(parsedCert.extensions);
    for (const ext of parsedCert.extensions) {
      if (ext.extnID === id_ce_basicConstraints) {
        const basicConstraints = AsnParser.parse(ext.extnValue, BasicConstraints);
        basicConstraintsCA = basicConstraints.cA;
      }
    }
  }

  return {
    issuer,
    subject,
    version: parsedCert.version,
    basicConstraintsCA,
    notBefore: parsedCert.validity.notBefore.getTime(),
    notAfter: parsedCert.validity.notAfter.getTime(),
  };
}
