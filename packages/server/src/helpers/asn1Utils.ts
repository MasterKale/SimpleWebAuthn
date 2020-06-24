import asn1 from '@lapo/asn1js';

/**
 * Decode an X.509 certificate's ASN1 document (e.g. attStmt.x5c[0])
 */
export function leafCertToASN1Object(leafCert: Buffer): ASN1Object {
  return asn1.decode(leafCert);
}

/**
 * Recursively map an ASN1 document to JSON
 */
export function asn1ObjectToJSON(asn1object: ASN1Object): JASN1 {
  const jasn: JASN1 = {
    type: asn1object.typeName(),
    data: [],
  };

  if (!asn1object.sub) {
    if (asn1object.typeName() === 'BIT_STRING' || asn1object.typeName() === 'OCTET_STRING')
      jasn.data = asn1object.stream.enc.slice(asn1object.posContent(), asn1object.posEnd());
    else jasn.data = asn1object.content();

    return jasn;
  }

  jasn.data = [];
  for (const sub of asn1object.sub) {
    jasn.data.push(asn1ObjectToJSON(sub));
  }

  return jasn;
}

/**
 * Find a specific extension in an ASN1 document by its OBJECT_IDENTIFIER
 */
export function findOID(asn1object: ASN1Object, oid: string): JASN1 | undefined {
  if (!asn1object.sub) {
    return;
  }

  for (const sub of asn1object.sub) {
    const type = sub.typeName();
    const content = sub.content();
    if (type !== 'OBJECT_IDENTIFIER' || (typeof content === 'string' && content.indexOf(oid) < 0)) {
      const result = findOID(sub, oid);
      if (result) {
        return result;
      }
    } else {
      return asn1ObjectToJSON(asn1object);
    }
  }
}

/**
 * Observed output from asn1.decode() relevant to the various helpers
 */
export type ASN1Object = {
  typeName: () => string;
  posContent: () => number;
  posEnd: () => number;
  content: () => string | null;
  stream: {
    enc: Buffer;
  };
  sub?: ASN1Object[];
};

/**
 * JSON-decoded values from an ASN1 document
 */
export type JASN1 = {
  type: string;
  data: JASN1[] | string | Buffer | null;
};
