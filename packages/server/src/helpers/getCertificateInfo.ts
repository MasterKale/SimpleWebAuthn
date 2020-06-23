/* eslint-disable-next-line */
// @ts-ignore 2305
import { X509, ASN1HEX, zulutodate } from 'jsrsasign';

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
export default function getCertificateInfo(
  pemCertificate: string,
  includeExtraInfo?: 'tpm' | 'android-key',
): CertificateInfo {
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
  const basicConstraintsCA = !!subjectCert.getExtBasicConstraints().cA;

  const toReturn: CertificateInfo = {
    issuer,
    subject,
    version,
    basicConstraintsCA,
    notBefore: zulutodate(subjectCert.getNotBefore()),
    notAfter: zulutodate(subjectCert.getNotAfter()),
    extendedKeyUsageIDs: subjectCert.getExtExtKeyUsageName(),
  };

  if (includeExtraInfo === 'tpm') {
    const tpmInfo = {
      subjectAltNamePresent: false,
      tcgAtTpmManufacturer: '',
      tcgAtTpmModel: '',
      tcgAtTpmVersion: '',
      extKeyUsage: '',
    };

    const asn1Dump = ASN1HEX.dump(subjectCert.hex);
    // console.log(asn1Dump);
    const asn1Lines: string[] = asn1Dump.split('\n');

    const subjectAltNameID = '2 5 29 17';
    const tcgAtTpmManufacturerID = '2 23 133 2 1';
    const tcgAtTpmModelID = '2 23 133 2 2';
    const tcgAtTpmVersionID = '2 23 133 2 3';
    const extKeyUsageID = '2 5 29 37';

    // Time to brute-force our way to victory
    for (let i = 0; i < asn1Lines.length; i += 1) {
      const line = asn1Lines[i];

      if (!tpmInfo.subjectAltNamePresent && line.indexOf(subjectAltNameID) >= 0) {
        // Value is on the next line
        tpmInfo.subjectAltNamePresent = decodeASN1Boolean(asn1Lines[i + 1].trim());
        i += 1;
      }

      if (!tpmInfo.tcgAtTpmManufacturer && line.indexOf(tcgAtTpmManufacturerID) >= 0) {
        // Value is on the next line
        tpmInfo.tcgAtTpmManufacturer = decodeASN1UTF8String(asn1Lines[i + 1].trim());
        i += 1;
      }

      if (!tpmInfo.tcgAtTpmModel && line.indexOf(tcgAtTpmModelID) >= 0) {
        // Value is on the next line
        tpmInfo.tcgAtTpmModel = decodeASN1UTF8String(asn1Lines[i + 1].trim());
        i += 1;
      }

      if (!tpmInfo.tcgAtTpmVersion && line.indexOf(tcgAtTpmVersionID) >= 0) {
        // Value is on the next line
        tpmInfo.tcgAtTpmVersion = decodeASN1UTF8String(asn1Lines[i + 1].trim());
        i += 1;
      }

      if (!tpmInfo.extKeyUsage && line.indexOf(extKeyUsageID) >= 0) {
        // Value is a few lines down
        tpmInfo.extKeyUsage = decodeASN1ObjectIdentifier(asn1Lines[i + 3]);
        i += 3;
      }
    }

    toReturn.tpmInfo = tpmInfo;
  }

  return toReturn;
}

/**
 * Some brute-force ASN.1 DER decode methods
 */

/**
 * Convert a value like "BOOLEAN TRUE" to true
 */
function decodeASN1Boolean(input: string): boolean {
  return input === 'BOOLEAN TRUE';
}

/**
 * Convert a value like "UTF8String 'id:FFFFF1D0'" to "id:FFFFF1D0"
 */
function decodeASN1UTF8String(input: string): string {
  const matched = /UTF8String '([\w:]+)'/.exec(input);

  if (!matched) {
    return '';
  }

  return matched[1];
}

/**
 * Convert a value like "ObjectIdentifier (2 23 133 8 3)" to "2.23.133.8.3"
 */
function decodeASN1ObjectIdentifier(input: string): string {
  const matched = /ObjectIdentifier \(([\d ]+)\)/.exec(input);

  if (!matched) {
    return '';
  }

  return matched[1].replace(/ /g, '.');
}
