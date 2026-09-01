import { assert, assertRejects } from '@std/assert';
import { FakeTime } from '@std/testing/time';

import { validateCertificatePath } from './validateCertificatePath.ts';
import { generateIntermediateCert, generateLeafCert, generateRootCert } from './tests/x509Utils.ts';

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
    issuer: maliciousRoot,
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
        [maliciousLeafCert.certificate.toString(), maliciousRoot.certificate.toString()],
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
    issuer: rootCert,
  });

  const validated = await validateCertificatePath(
    [leafCert.certificate.toString()],
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
    issuer: rootCert,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert.certificate.toString()],
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
    issuer: rootCert,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert.certificate.toString()],
        [rootCert.certificate.toString()],
      ),
    Error,
    'No specified trust anchor was valid',
  );
});

Deno.test('should raise on expired leaf certificate', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const rootCert = await generateRootCert({ notBefore, notAfter });
  const leafCert = await generateLeafCert({
    notBefore,
    notAfter: new Date('2026-06-07'), // <-- earlier than _fakedNow
    issuer: rootCert,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert.certificate.toString()],
        [rootCert.certificate.toString()],
      ),
    Error,
    'certificate out of validity period in x5c',
  );
});

Deno.test('should raise on expired trust anchor certificate', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const rootCert = await generateRootCert({
    notBefore,
    notAfter: new Date('2026-06-07'), // <-- earlier than _fakedNow
  });
  const leafCert = await generateLeafCert({
    notBefore,
    notAfter,
    issuer: rootCert,
  });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert.certificate.toString()],
        [rootCert.certificate.toString()],
      ),
    Error,
    'No specified trust anchor was valid',
  );
});

Deno.test('should raise when x5c does not chain to trust anchor', async () => {
  using _fakedNow = new FakeTime(new Date('2026-06-08'));

  const notBefore = new Date('2026-06-07');
  const notAfter = new Date('2026-06-09');

  const rootCert1 = await generateRootCert({ notBefore, notAfter });
  const leafCert1 = await generateLeafCert({
    notBefore,
    notAfter,
    issuer: rootCert1,
  });

  const rootCert2 = await generateRootCert({ notBefore, notAfter });

  await assertRejects(
    () =>
      validateCertificatePath(
        [leafCert1.certificate.toString()],
        [rootCert2.certificate.toString()],
      ),
    Error,
    'x5c could not be chained',
  );
});

Deno.test('should validate path from partial list of x5c entries to anchor', async () => {
  using _fakedNow = new FakeTime(new Date('2026-08-30'));

  const notBefore = new Date('2026-08-29');
  const notAfter = new Date('2026-08-31');

  /**
   * The cert chain being crafted here:
   *
   * leaf cert
   * v
   * intermediate cert
   * v
   * r46 CA cert
   * v
   * cross-sign cert
   * v
   * r3 CA cert
   */

  const rootCert3 = await generateRootCert({ notBefore, notAfter });
  const rootCert46 = await generateRootCert({ notBefore, notAfter });

  const crossSignCertR46ToR3 = await generateIntermediateCert({
    notBefore,
    notAfter,
    subject: rootCert46,
    issuer: rootCert3,
  });

  const intermediateCert = await generateIntermediateCert({
    notBefore,
    notAfter,
    issuer: rootCert46,
  });

  const leafCert = await generateLeafCert({
    notBefore,
    notAfter,
    issuer: intermediateCert,
  });

  const x5c = [
    leafCert.certificate.toString(),
    intermediateCert.certificate.toString(),
    crossSignCertR46ToR3.certificate.toString(),
  ];

  // Ensure that both root certs can form a valid chain from x5c
  assert(await validateCertificatePath(x5c, [rootCert46.certificate.toString()]));
  assert(await validateCertificatePath(x5c, [rootCert3.certificate.toString()]));
});
