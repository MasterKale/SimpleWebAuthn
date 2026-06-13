import { assert, assertRejects } from '@std/assert';
import { FakeTime } from '@std/testing/time';

import { validateCertificatePath } from './validateCertificatePath.ts';
import { generateLeafCert, generateRootCert } from './tests/x509Utils.ts';

Deno.test('should reject x5c containing self-signed root certificate', async () => {
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
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const maliciousRoot = await generateRootCert({
    name: 'CN=Malicious Unit Test Self-Signed Root Cert',
    notBefore,
    notAfter,
  });

  const maliciousLeafCert = await generateLeafCert({
    subject: 'CN=Malicious Unit Test Leaf Cert',
    notBefore,
    notAfter,
    chainsToCertificate: maliciousRoot.certificate,
    chainsToPrivateKey: maliciousRoot.keys.privateKey,
  });

  const realTrustAnchor = await generateRootCert({
    name: 'CN=SimpleWebAuthn Unit Test Self-Signed Root Cert',
    notBefore,
    notAfter,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        // x5c
        [maliciousLeafCert.toString(), maliciousRoot.certificate.toString()],
        // trust anchors
        [realTrustAnchor.certificate.toString()],
      ),
    Error,
    'x5c could not be chained to any specified trust anchor',
  );
});

Deno.test('should validate valid certificate chain', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const rootCert = await generateRootCert({ notBefore, notAfter });
  const leafCert = await generateLeafCert({
    notBefore,
    notAfter,
    chainsToCertificate: rootCert.certificate,
    chainsToPrivateKey: rootCert.keys.privateKey,
  });

  const validated = await validateCertificatePath(
    [leafCert.toString()],
    [rootCert.certificate.toString()],
  );

  assert(validated);
});

Deno.test('should raise on not-yet-valid leaf certificate', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const rootCert = await generateRootCert({ notBefore, notAfter });
  const leafCert = await generateLeafCert({
    notBefore: new Date('2026-06-09'), // <-- later than _fakedNow
    notAfter,
    chainsToCertificate: rootCert.certificate,
    chainsToPrivateKey: rootCert.keys.privateKey,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert.toString()],
        [rootCert.certificate.toString()],
      ),
    Error,
    'certificate out of validity period in x5c',
  );
});

Deno.test('should raise on not-yet-valid trust anchor certificate', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const rootCert = await generateRootCert({
    notBefore: new Date('2026-06-09'), // <-- later than _fakedNow
    notAfter,
  });
  const leafCert = await generateLeafCert({
    notBefore,
    notAfter,
    chainsToCertificate: rootCert.certificate,
    chainsToPrivateKey: rootCert.keys.privateKey,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert.toString()],
        [rootCert.certificate.toString()],
      ),
    Error,
    'No specified trust anchor was valid',
  );
});
