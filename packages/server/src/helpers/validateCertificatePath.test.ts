import { assertRejects } from '@std/assert';
import { FakeTime } from '@std/testing/time';

import * as x509 from '@peculiar/x509';

import { getWebCrypto } from './iso/isoCrypto/getWebCrypto.ts';
import { validateCertificatePath } from './validateCertificatePath.ts';

const webCrypto = await getWebCrypto();

/**
 * This test generates X.509 certificates to ensure that the following hypothetical/malicious
 * certificate chain in x5c will be rejected:
 *
 * [
 *   x5c[0] (maliciousLeaf, signed by maliciousRoot)
 *   x5c[1] (maliciousRoot, self-signed root cert)
 *   realTrustAnchor
 * ]
 *
 * The certs don't chain back to realTrustAnchor and so that attestation statement should be
 * rejected.
 */
Deno.test('should reject x5c containing self-signed root certificate', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08T00:00:00.000Z'));

  const keyAlg: EcKeyGenParams = { name: 'ECDSA', namedCurve: 'P-256' };
  const signingAlg: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

  const maliciousLeafKeys = await webCrypto.subtle.generateKey(keyAlg, false, ['sign', 'verify']);
  const maliciousRootKeys = await webCrypto.subtle.generateKey(keyAlg, false, ['sign', 'verify']);
  const realTrustAnchorKeys = await webCrypto.subtle.generateKey(keyAlg, false, ['sign', 'verify']);

  const notBefore = new Date('2026-06-07T00:00:00.000Z');
  const notAfter = new Date('2026-06-09T00:00:00.000Z');

  const maliciousSelfSignedRootCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=Malicious Unit Test Self-Signed Root Cert',
    notBefore,
    notAfter,
    signingAlgorithm: signingAlg,
    keys: maliciousRootKeys,
    extensions: [
      // Critical: Tell the world this is a CA and can sign things
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
    ],
  });

  const maliciousLeafCert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=Malicious Unit Test Leaf Cert',
    issuer: maliciousSelfSignedRootCert.subject,
    notBefore,
    notAfter,
    signingAlgorithm: signingAlg,
    signingKey: maliciousRootKeys.privateKey,
    publicKey: maliciousLeafKeys.publicKey,
    extensions: [
      // Explicitly state this is an end-entity (not a CA)
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
    ],
  });

  const realTrustAnchorCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=SimpleWebAuthn Unit Test Self-Signed Root Cert',
    notBefore,
    notAfter,
    signingAlgorithm: signingAlg,
    keys: realTrustAnchorKeys,
    extensions: [
      // Critical: Tell the world this is a CA and can sign things
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign, true),
    ],
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        // x5c
        [maliciousLeafCert.toString(), maliciousSelfSignedRootCert.toString()],
        // trust anchors
        [realTrustAnchorCert.toString()],
      ),
    Error,
    'x5c could not be chained to any specified trust anchor',
  );
});
