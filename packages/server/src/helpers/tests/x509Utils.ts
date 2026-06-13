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
      // Critical: Tell the world this is a CA and can sign things
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
    ],
  });

  return {
    certificate,
    keys,
  };
}

/**
 * Generate an X.509 end-entity "leaf" certificate
 */
export async function generateLeafCert(opts: {
  /** Before when the cert should not be valid */
  notBefore: Date;
  /** After when the cert should not be valid */
  notAfter: Date;
  /** The certificate that this certificate will chain to */
  chainsToCertificate: x509.X509Certificate;
  /** The private key of the `chainsToCertificate` certificate */
  chainsToPrivateKey: CryptoKey;
  /** The Subject for this certificate */
  subject?: string;
  /** The algorithm used for the certificate's keypair */
  keyAlgorithm?: EcKeyGenParams;
  /** The algorithm used for generating a signature over the certificate */
  signingAlgorithm?: Algorithm | EcdsaParams;
}): Promise<x509.X509Certificate> {
  const {
    notBefore,
    notAfter,
    chainsToCertificate,
    chainsToPrivateKey,
    subject = 'CN=SimpleWebAuthn Unit Test Leaf Cert',
    keyAlgorithm = defaultKeyAlgorithm,
    signingAlgorithm = defaultSigningAlgorithm,
  } = opts;
  const webCrypto = await getWebCrypto();

  const keys = await webCrypto.subtle.generateKey(keyAlgorithm, false, ['sign', 'verify']);

  const certificate = await x509.X509CertificateGenerator.create({
    subject,
    notBefore,
    notAfter,
    issuer: chainsToCertificate.subject,
    signingKey: chainsToPrivateKey,
    signingAlgorithm,
    publicKey: keys.publicKey,
    extensions: [
      // Explicitly state this is an end-entity (not a CA)
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  });

  return certificate;
}
