import 'reflect-metadata';
import { assert, assertFalse, assertRejects } from '@std/assert';
import { FakeTime } from '@std/testing/time';
import { assertSpyCallArgs, assertSpyCalls, stub } from '@std/testing/mock';
import { AuthorityKeyIdentifierExtension, type X509Certificate } from '@peculiar/x509';

import { isCertRevoked } from './isCertRevoked.ts';
import { _fetchInternals } from './fetch.ts';
import {
  generateCRL,
  generateCRLDistributionPointsExtension,
  generateIntermediateCert,
  generateLeafCert,
  generateRootCert,
} from './tests/x509Utils.ts';

const CRL_URL = 'https://example.com/test.crl';

/**
 * Generate a self-signed root cert and the leaf cert it issued, with the leaf cert carrying
 * an AuthorityKeyIdentifier extension, and a CRLDistributionPoints extension pointing at CRL_URL.
 */
async function generateLeafAndRoot(opts: { notBefore: Date; notAfter: Date }): Promise<{
  leaf: { certificate: X509Certificate; keys: CryptoKeyPair };
  root: { certificate: X509Certificate; keys: CryptoKeyPair };
}> {
  const { notBefore, notAfter } = opts;

  const root = await generateRootCert({ notBefore, notAfter });
  const authorityKeyIdentifier = await AuthorityKeyIdentifierExtension.create(root.keys.publicKey);
  const leaf = await generateLeafCert({
    notBefore,
    notAfter,
    issuer: root,
    extensions: [
      authorityKeyIdentifier,
      generateCRLDistributionPointsExtension([CRL_URL]),
    ],
  });

  return { root, leaf };
}

Deno.test('should report a cert as revoked when its serial is in a validly-signed CRL', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  const crl = await generateCRL({
    issuer: root,
    thisUpdate: notBefore,
    nextUpdate: notAfter,
    revokedSerialNumbers: [leaf.certificate.serialNumber],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(crl.rawData)),
  );

  const revoked = await isCertRevoked(leaf.certificate, root.certificate);

  assert(revoked);
  assertSpyCallArgs(_mockFetch, 0, [CRL_URL]);
});

Deno.test('should report a cert as not revoked when its serial is absent from a validly-signed CRL', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  const crl = await generateCRL({
    issuer: root,
    thisUpdate: notBefore,
    nextUpdate: notAfter,
    revokedSerialNumbers: [],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(crl.rawData)),
  );

  const revoked = await isCertRevoked(leaf.certificate, root.certificate);

  assertFalse(revoked);
});

Deno.test('should reject when a fetched CRL was not signed by the given issuer', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  const attackerRoot = await generateRootCert({ notBefore, notAfter });
  const attackerCRL = await generateCRL({
    issuer: attackerRoot,
    thisUpdate: notBefore,
    nextUpdate: notAfter,
    revokedSerialNumbers: [leaf.certificate.serialNumber],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(attackerCRL.rawData)),
  );

  await assertRejects(() => isCertRevoked(leaf.certificate, root.certificate));
});

Deno.test('should report a cert as not revoked when the CRL is malformed', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(new TextEncoder().encode('not a real crl'))),
  );

  const revoked = await isCertRevoked(leaf.certificate, root.certificate);

  assertFalse(revoked);
});

Deno.test('should report a cert as not revoked when the CRL cannot be fetched', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.reject(new Error('Cannot resolve hostname')),
  );

  const revoked = await isCertRevoked(leaf.certificate, root.certificate);

  assertFalse(revoked);
});

Deno.test('should report a cert as not revoked, and skip fetch, when it has no CRLDistributionPoints extension', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const root = await generateRootCert({ notBefore, notAfter });
  const leaf = await generateLeafCert({
    notBefore,
    notAfter,
    issuer: root,
    extensions: [
      await AuthorityKeyIdentifierExtension.create(root.keys.publicKey),
    ],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(new ArrayBuffer(0))),
  );

  const revoked = await isCertRevoked(leaf.certificate, root.certificate);

  assertFalse(revoked);
  assertSpyCalls(_mockFetch, 0);
});

Deno.test('should only fetch the CRL once per cert authority within the nextUpdate window', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  const crl = await generateCRL({
    issuer: root,
    thisUpdate: notBefore,
    nextUpdate: notAfter,
    revokedSerialNumbers: [leaf.certificate.serialNumber],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(crl.rawData)),
  );

  const firstResult = await isCertRevoked(leaf.certificate, root.certificate);
  const secondResult = await isCertRevoked(leaf.certificate, root.certificate);

  assert(firstResult);
  assert(secondResult);
  assertSpyCalls(_mockFetch, 1);
});

Deno.test('should refetch the CRL after its nextUpdate has passed', async () => {
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-08');
  const nextUpdate = new Date('2026-09-09');

  const { root, leaf } = await generateLeafAndRoot({ notBefore, notAfter });

  const crl = await generateCRL({
    issuer: root,
    thisUpdate: notBefore,
    nextUpdate,
    revokedSerialNumbers: [],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(crl.rawData)),
  );

  const _fakedThen = new FakeTime(new Date('2026-09-07'));
  await isCertRevoked(leaf.certificate, root.certificate);
  // Call 1: Original request for CRL
  assertSpyCalls(_mockFetch, 1);
  assertSpyCallArgs(_mockFetch, 0, [CRL_URL]);
  _fakedThen.restore();

  // Past the CRL's nextUpdate, so the cached result must not be reused
  using _fakedNow = new FakeTime(new Date('2026-09-09'));
  await isCertRevoked(leaf.certificate, root.certificate);
  // Call 2: Request for refreshed CRL
  assertSpyCalls(_mockFetch, 2);
  assertSpyCallArgs(_mockFetch, 1, [CRL_URL]);
});

Deno.test('should report a cert as not revoked, and skip fetch, when no issuer cert is provided', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  // This root certificate is only used to sign the intermediate cert
  const { root } = await generateLeafAndRoot({ notBefore, notAfter });

  // This is what the Relying Party sets up as the trust anchor
  const trustAnchorIntermediate = await generateIntermediateCert({
    notBefore,
    notAfter,
    issuer: root,
    extensions: [
      await AuthorityKeyIdentifierExtension.create(root.keys.publicKey),
      generateCRLDistributionPointsExtension([CRL_URL]),
    ],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    () => Promise.resolve(new Response(new ArrayBuffer(0))),
  );

  /**
   * The certificate chain ends with an intermediate certificate for the trust anchor. We have no
   * self-signed root cert to verify the intermediate cert's CRL's signature to tell if the
   * intermediate cert is revoked so soft-fail.
   */
  const revoked = await isCertRevoked(trustAnchorIntermediate.certificate, undefined);

  assertFalse(revoked);
  assertSpyCalls(_mockFetch, 0);
});

Deno.test('should check all CRL URLs in issuer cert for revocation status', async () => {
  using _fakedNow = new FakeTime(new Date('2026-09-08'));
  const notBefore = new Date('2026-09-07');
  const notAfter = new Date('2026-09-09');

  const CRL_URL_2 = 'https://example.com/2/test.crl';

  const root = await generateRootCert({ notBefore, notAfter });
  const authorityKeyIdentifier = await AuthorityKeyIdentifierExtension.create(root.keys.publicKey);
  const leaf = await generateLeafCert({
    notBefore,
    notAfter,
    issuer: root,
    extensions: [
      authorityKeyIdentifier,
      generateCRLDistributionPointsExtension([CRL_URL, CRL_URL_2]),
    ],
  });

  const crl1 = await generateCRL({
    issuer: root,
    thisUpdate: notBefore,
    nextUpdate: notAfter,
    revokedSerialNumbers: [],
  });

  // Putting revocation in the second CRL will help ensure it gets pulled and revokes the cert
  const crl2 = await generateCRL({
    issuer: root,
    thisUpdate: notBefore,
    nextUpdate: notAfter,
    revokedSerialNumbers: [leaf.certificate.serialNumber],
  });

  using _mockFetch = stub(
    _fetchInternals,
    'stubThis',
    (url: string) => {
      if (url === CRL_URL) {
        return Promise.resolve(new Response(crl1.rawData));
      } else {
        return Promise.resolve(new Response(crl2.rawData));
      }
    },
  );

  const revoked = await isCertRevoked(leaf.certificate, root.certificate);

  assert(revoked);
  assertSpyCallArgs(_mockFetch, 0, [CRL_URL]);
  assertSpyCallArgs(_mockFetch, 1, [CRL_URL_2]);
});
