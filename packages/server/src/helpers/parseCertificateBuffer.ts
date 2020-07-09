import { AsnParser } from '@peculiar/asn1-schema';
import { Certificate } from '@peculiar/asn1-x509';

/**
 * Parse a certificate buffer ASN.1 data structure into something more friendly
 */
export default function parseCertificateASN1(certificate: Buffer): Certificate {
  return AsnParser.parse(certificate, Certificate);
}
