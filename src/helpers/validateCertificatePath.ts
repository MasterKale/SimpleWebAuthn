export default function validateCertificatePath(certificates: any[]) {
  console.log('certificates', certificates);
  return false;
  // TODO: Re-investigate this if we decide to "use MDS or Metadata Statements"
  // console.debug('validating certificate path');

  // const uniqueCerts = new Set(certificates);

  // if (uniqueCerts.size !== certificates.length) {
  //   throw new Error('Certificate path could not be verified due to duplicate certificates');
  // }

  // certificates.forEach((subjectPEM, index) => {
  //   const subjectCert = new jsrsasign.X509();
  //   subjectCert.readCertPEM(subjectPEM);

  //   let issuerPEM;
  //   if (index + 1 >= certificates.length) {
  //     console.debug('using subjectPEM as issuerPEM');
  //     issuerPEM = subjectPEM;
  //   } else {
  //     console.debug('using next cert as issuerPEM');
  //     issuerPEM = certificates[index + 1];
  //   }

  //   const issuerCert = new jsrsasign.X509();
  //   issuerCert.readCertPEM(issuerPEM);

  //   const subjectCertString = subjectCert.getSubjectString();
  //   const issuerCertString = issuerCert.getSubjectString();
  //   if (subjectCertString !== issuerCertString) {
  //     console.error('subject strings didn\'t match');
  //     console.debug('subjectCertString:', subjectCertString);
  //     console.debug('issuerCertString:', issuerCertString);
  //     throw new Error('Certificate issuers didn\'t match');
  //   }

  //   const subjectCertStruct = jsrsasign.ASN1HEX.getTLVbyList(subjectCert.hex, 0, [0]);
  //   const algorithm = subjectCert.getSignatureAlgorithmField();
  //   const signatureHex = subjectCert.getSignatureValueHex();

  //   const Signature = new jsrsasign.crypto.Signature({ alg: algorithm });
  //   Signature.init(issuerPEM);
  //   Signature.updateHex(subjectCertStruct);

  //   const sigVerified = Signature.verify(signatureHex);
  //   if (!sigVerified) {
  //     console.error('failed to validate certificate path');
  //     console.debug('sigVerified:', sigVerified);
  //     throw new Error('Certificate path could not be validated');
  //   }
  // });

  // return true;
}
