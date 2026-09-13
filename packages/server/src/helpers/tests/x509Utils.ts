import 'reflect-metadata';
import * as x509 from '@peculiar/x509';

import { getWebCrypto } from '../iso/isoCrypto/getWebCrypto.ts';

/**
 * Default algorithms used for certs
 */
const defaultKeyAlgorithm: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
const defaultSigningAlgorithm: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

/**
 * Generate a self-signed X.509 root certificate
 */
export async function generateRootCert(opts: {
  /** Before when the cert should not be valid */
  notBefore: Date;
  /** After when the cert should not be valid */
  notAfter: Date;
  /** The Subject and Issuer for this certificate */
  name?: string;
  /** The algorithm used for the certificate's keypair */
  keyAlgorithm?: EcKeyGenParams;
  /** The algorithm used for generating a signature over the certificate */
  signingAlgorithm?: Algorithm | EcdsaParams;
}): Promise<{ certificate: x509.X509Certificate; keys: CryptoKeyPair }> {
  const {
    notBefore,
    notAfter,
    name = 'CN=SimpleWebAuthn Unit Test Self-Signed Root Cert',
    keyAlgorithm = defaultKeyAlgorithm,
    signingAlgorithm = defaultSigningAlgorithm,
  } = opts;
  const webCrypto = await getWebCrypto();

  const keys = await webCrypto.subtle.generateKey(keyAlgorithm, false, ['sign', 'verify']);

  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    name,
    notBefore,
    notAfter,
    signingAlgorithm,
    keys: keys,
    extensions: [
      // Critical: Tell the world this is a CA cert that can sign other certs
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  return { certificate, keys };
}

/**
 * Generate a cert that is signed by another cert and can sign other certs to form a chain
 */
export async function generateIntermediateCert(opts: {
  /** Before when the cert should not be valid */
  notBefore: Date;
  /** After when the cert should not be valid */
  notAfter: Date;
  /** The certificate (and its keys) that this certificate will chain to */
  issuer: { certificate: x509.X509Certificate; keys: CryptoKeyPair };
  /** The optional subject for this certificate */
  subject?: { certificate: x509.X509Certificate; keys: CryptoKeyPair };
  /** The algorithm used for the certificate's keypair */
  keyAlgorithm?: EcKeyGenParams;
  /** The algorithm used for generating a signature over the certificate */
  signingAlgorithm?: Algorithm | EcdsaParams;
  /** Additional certificate extensions (e.g. AuthorityKeyIdentifier, CRLDistributionPoints) */
  extensions?: x509.Extension[];
}): Promise<{ certificate: x509.X509Certificate; keys: CryptoKeyPair }> {
  const {
    notBefore,
    notAfter,
    issuer,
    subject,
    keyAlgorithm = defaultKeyAlgorithm,
    signingAlgorithm = defaultSigningAlgorithm,
    extensions = [],
  } = opts;

  const webCrypto = await getWebCrypto();

  const certSubject = subject?.certificate.subject ??
    'CN=SimpleWebAuthn Unit Test Intermediate Cert';

  // Use the provided keys, otherwise generate a new keypair
  const certKeys = subject?.keys ??
    await webCrypto.subtle.generateKey(keyAlgorithm, false, ['sign', 'verify']);

  const certificate = await x509.X509CertificateGenerator.create({
    subject: certSubject,
    notBefore,
    notAfter,
    issuer: issuer.certificate.subject,
    signingKey: issuer.keys.privateKey,
    signingAlgorithm,
    publicKey: certKeys.publicKey,
    extensions: [
      // Explicitly state this cert can sign other certs
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
      ...extensions,
    ],
  });

  return { certificate, keys: certKeys };
}

/**
 * Generate an X.509 end-entity "leaf" certificate
 */
export async function generateLeafCert(opts: {
  /** Before when the cert should not be valid */
  notBefore: Date;
  /** After when the cert should not be valid */
  notAfter: Date;
  /** The certificate (and its keys) that this certificate will chain to */
  issuer: { certificate: x509.X509Certificate; keys: CryptoKeyPair };
  /** The Subject for this certificate */
  subject?: string;
  /** The algorithm used for the certificate's keypair */
  keyAlgorithm?: EcKeyGenParams;
  /** The algorithm used for generating a signature over the certificate */
  signingAlgorithm?: Algorithm | EcdsaParams;
  /** Additional certificate extensions (e.g. AuthorityKeyIdentifier, CRLDistributionPoints) */
  extensions?: x509.Extension[];
}): Promise<{ certificate: x509.X509Certificate; keys: CryptoKeyPair }> {
  const {
    notBefore,
    notAfter,
    issuer,
    subject = 'CN=SimpleWebAuthn Unit Test Leaf Cert',
    keyAlgorithm = defaultKeyAlgorithm,
    signingAlgorithm = defaultSigningAlgorithm,
    extensions = [],
  } = opts;
  const webCrypto = await getWebCrypto();

  const keys = await webCrypto.subtle.generateKey(keyAlgorithm, false, ['sign', 'verify']);

  const certificate = await x509.X509CertificateGenerator.create({
    subject,
    notBefore,
    notAfter,
    issuer: issuer.certificate.subject,
    signingKey: issuer.keys.privateKey,
    signingAlgorithm,
    publicKey: keys.publicKey,
    extensions: [
      // Explicitly state this is an end-entity and thus cannot sign other certs
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      ...extensions,
    ],
  });

  return { certificate, keys };
}

/**
 * Build a CRLDistributionPoints extension
 */
export function generateCRLDistributionPointsExtension(
  urls: string[],
): x509.CRLDistributionPointsExtension {
  return new x509.CRLDistributionPointsExtension(urls);
}

/**
 * Generate a signed X.509 CRL (Certificate Revocation List)
 */
export function generateCRL(opts: {
  /** The certificate (and its keys) that will sign this CRL */
  issuer: { certificate: x509.X509Certificate; keys: CryptoKeyPair };
  /** When the CRL was published */
  thisUpdate?: Date;
  /** When the next CRL update is expected */
  nextUpdate?: Date;
  /** Hex-formatted serial numbers of certs to list as revoked */
  revokedSerialNumbers?: string[];
  /** The algorithm used for generating a signature over the CRL */
  signingAlgorithm?: Algorithm | EcdsaParams;
}): Promise<x509.X509Crl> {
  const {
    issuer,
    thisUpdate,
    nextUpdate,
    revokedSerialNumbers,
    signingAlgorithm = defaultSigningAlgorithm,
  } = opts;

  return x509.X509CrlGenerator.create({
    issuer: issuer.certificate.subject,
    thisUpdate,
    nextUpdate,
    signingAlgorithm,
    signingKey: issuer.keys.privateKey,
    entries: revokedSerialNumbers?.map((serialNumber) => ({ serialNumber })),
  });
}
