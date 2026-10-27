import { assertEquals, assertNotEquals, assertRejects } from '@std/assert';
import { afterEach, beforeEach, describe, it } from '@std/testing/bdd';
import {
  assertSpyCallArg,
  assertSpyCalls,
  returnsNext,
  spy,
  type Stub,
  stub,
} from '@std/testing/mock';

import { _fetchInternals } from '../helpers/fetch.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';
import { generateLeafCert, generateRootCert } from '../helpers/tests/x509Utils.ts';

import { BaseMetadataService, MetadataService } from './metadataService.ts';
import { SettingsService } from './settingsService.ts';
import type { MetadataStatement } from '../metadata/mdsTypes.ts';
import type { ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';

let mockFetch: Stub;

describe('Method: initialize()', () => {
  beforeEach(() => {
    mockFetch = stub(_fetchInternals, 'stubThis');
  });

  afterEach(() => {
    mockFetch.restore();
  });

  it('should default to querying MDS v3', async () => {
    await MetadataService.initialize();

    assertSpyCalls(mockFetch, 1);
    assertSpyCallArg(mockFetch, 0, 0, 'https://mds.fidoalliance.org/?localCopySerial=0');
  });

  it('should query provided MDS server URLs', async () => {
    const mdsServers = ['https://custom-mds1.com', 'https://custom-mds2.com'];

    await MetadataService.initialize({ mdsServers });

    assertSpyCalls(mockFetch, mdsServers.length);
    assertSpyCallArg(mockFetch, 0, 0, `${mdsServers[0]}/?localCopySerial=0`);
    assertSpyCallArg(mockFetch, 1, 0, `${mdsServers[1]}/?localCopySerial=0`);
  });

  it('should not query any servers on empty list of URLs', async () => {
    await MetadataService.initialize({ mdsServers: [] });

    assertSpyCalls(mockFetch, 0);
  });

  it('should load local statements', async () => {
    await MetadataService.initialize({
      statements: [localStatement],
    });

    const statement = await MetadataService.getStatement(localStatementAAGUID);

    assertEquals(statement, localStatement);
  });
});

describe('Method: getStatement()', () => {
  it('should return undefined if service not initialized', async () => {
    // For lack of a way to "uninitialize" the singleton, create a new instance
    const service = new BaseMetadataService();
    const statement = await service.getStatement('not-a-real-aaguid');

    assertEquals(statement, undefined);
  });

  it('should return undefined if aaguid is undefined', async () => {
    // TypeScript will prevent you from passing `undefined`, but JS won't so test it
    // @ts-ignore 2345
    const statement = await MetadataService.getStatement(undefined);

    assertEquals(statement, undefined);
  });

  it('should throw after initialization on AAGUID with no statement', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      statements: [],
    });

    await assertRejects(
      () => MetadataService.getStatement('not-a-real-aaguid'),
    );
  });

  it('should return undefined after initialization on AAGUID with no statement and verificationMode is "permissive"', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      statements: [],
      verificationMode: 'permissive',
    });

    const statement = await MetadataService.getStatement('not-a-real-aaguid');

    assertEquals(statement, undefined);
  });
});

describe('Method: getProviderMetadata()', () => {
  // Built lazily because `localStatement` is declared at the bottom of this file
  const providerStatement = (): MetadataStatement => ({
    ...localStatement,
    friendlyNames: { en: 'Local Provider', fr: 'Fournisseur local' },
    icon: 'data:image/png;base64,icon',
    iconDark: 'data:image/svg+xml;base64,iconDark',
    providerLogoLight: 'data:image/svg+xml;base64,logoLight',
    providerLogoDark: 'data:image/svg+xml;base64,logoDark',
  });
  const providerMetadata: ProviderMetadata = {
    friendlyNames: { en: 'Local Provider', fr: 'Fournisseur local' },
    icon: 'data:image/png;base64,icon',
    iconDark: 'data:image/svg+xml;base64,iconDark',
    providerLogoLight: 'data:image/svg+xml;base64,logoLight',
    providerLogoDark: 'data:image/svg+xml;base64,logoDark',
  };

  it('should return undefined if service not initialized', async () => {
    const service = new BaseMetadataService();
    const metadata = await service.getProviderMetadata('not-a-real-aaguid');

    assertEquals(metadata, undefined);
  });

  it('should return undefined if aaguid is undefined', async () => {
    await MetadataService.initialize({ mdsServers: [], statements: [providerStatement()] });

    // @ts-ignore: intentionally passing a bad value
    const metadata = await MetadataService.getProviderMetadata(undefined);

    assertEquals(metadata, undefined);
  });

  it('should derive provider metadata from a local statement', async () => {
    await MetadataService.initialize({ mdsServers: [], statements: [providerStatement()] });

    const metadata = await MetadataService.getProviderMetadata(localStatementAAGUID);

    assertEquals(metadata, providerMetadata);
  });

  it('should accept the AAGUID as a Uint8Array', async () => {
    await MetadataService.initialize({ mdsServers: [], statements: [providerStatement()] });

    const aaguidBytes = new Uint8Array([
      0x91,
      0xdf,
      0xea,
      0xd7,
      0x95,
      0x9e,
      0x44,
      0x75,
      0xad,
      0x26,
      0x9b,
      0x0d,
      0x48,
      0x2b,
      0xe0,
      0x89,
    ]);
    const metadata = await MetadataService.getProviderMetadata(aaguidBytes);

    assertEquals(metadata, providerMetadata);
  });

  it('should throw for an AAGUID with no statement when verificationMode is "strict"', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      statements: [providerStatement()],
      verificationMode: 'strict',
    });

    await assertRejects(() => MetadataService.getProviderMetadata('not-a-real-aaguid'));
  });

  it('should return undefined for an AAGUID with no statement when verificationMode is "permissive"', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      statements: [providerStatement()],
      verificationMode: 'permissive',
    });

    const metadata = await MetadataService.getProviderMetadata('not-a-real-aaguid');

    assertEquals(metadata, undefined);
  });

  it('should not query any convenience MDS servers', async () => {
    const mockFetch = stub(_fetchInternals, 'stubThis');

    try {
      await MetadataService.initialize({ mdsServers: [], statements: [providerStatement()] });
      await MetadataService.getProviderMetadata(localStatementAAGUID);

      assertSpyCalls(mockFetch, 0);
    } finally {
      mockFetch.restore();
    }
  });
});

describe('Behavior: BLOB refresh', () => {
  const mdsServerURL = 'https://mds.example.com/';
  let mockFetch: Stub;
  let originalMDSRootCerts: string[];
  const refreshableAAGUID = '00000000-0000-0000-0000-000000000001';

  beforeEach(async () => {
    /**
     * Our BLOBs are signed by certs generated at runtime, so temporarily trust the root cert they
     * chain back to. No CRL is specified for these certs, so revocation checking won't reach out
     * to the network either.
     */
    const { rootCertPEM } = await getBLOBSigner();
    originalMDSRootCerts = SettingsService.getRootCertificates({ identifier: 'mds' });
    SettingsService.setRootCertificates({ identifier: 'mds', certificates: [rootCertPEM] });
  });

  afterEach(() => {
    SettingsService.setRootCertificates({
      identifier: 'mds',
      certificates: originalMDSRootCerts,
    });
    mockFetch.restore();
  });

  it('should return an up-to-date statement after refreshing a stale BLOB', async () => {
    const staleStatement: MetadataStatement = {
      ...localStatement,
      aaguid: refreshableAAGUID,
      description: 'Statement from the stale BLOB',
      authenticatorVersion: 1,
    };
    const freshStatement: MetadataStatement = {
      ...localStatement,
      aaguid: refreshableAAGUID,
      description: 'Statement from the refreshed BLOB',
      authenticatorVersion: 2,
    };

    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        // The BLOB cached during initialization, which expired in the past
        generateBLOBResponse({ no: 1, nextUpdate: '2023-01-01', statement: staleStatement }),
        // The BLOB that should get downloaded when `getStatement()` notices the staleness
        generateBLOBResponse({ no: 2, nextUpdate: '2999-01-01', statement: freshStatement }),
      ]),
    );

    await MetadataService.initialize({ mdsServers: [mdsServerURL] });

    assertSpyCalls(mockFetch, 1);

    const statement = await MetadataService.getStatement(refreshableAAGUID);

    // The stale BLOB should have been re-downloaded...
    assertSpyCalls(mockFetch, 2);
    assertSpyCallArg(mockFetch, 1, 0, `${mdsServerURL}?localCopySerial=1`);
    // ...and the statement from the newer BLOB returned
    assertEquals(statement, freshStatement);
    assertNotEquals(statement, staleStatement);
  });

  it('should return up-to-date provider metadata after refreshing a stale BLOB', async () => {
    const staleStatement: MetadataStatement = {
      ...localStatement,
      aaguid: refreshableAAGUID,
      friendlyNames: { en: 'Stale Name' },
    };
    const freshStatement: MetadataStatement = {
      ...localStatement,
      aaguid: refreshableAAGUID,
      friendlyNames: { en: 'Fresh Name' },
    };

    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        generateBLOBResponse({ no: 1, nextUpdate: '2023-01-01', statement: staleStatement }),
        generateBLOBResponse({ no: 2, nextUpdate: '2999-01-01', statement: freshStatement }),
      ]),
    );

    await MetadataService.initialize({ mdsServers: [mdsServerURL] });

    const metadata = await MetadataService.getProviderMetadata(refreshableAAGUID);

    assertSpyCalls(mockFetch, 2);
    assertEquals(metadata?.friendlyNames, { en: 'Fresh Name' });
  });

  describe('stale BLOB handling', () => {
    const otherAAGUID = '00000000-0000-0000-0000-000000000002';
    let statementV1: MetadataStatement;
    let statementV2: MetadataStatement;
    let otherStatement: MetadataStatement;

    // Built here because `localStatement` is declared at the bottom of this file
    beforeEach(() => {
      statementV1 = { ...localStatement, aaguid: refreshableAAGUID, description: 'Statement v1' };
      statementV2 = { ...statementV1, description: 'Statement v2' };
      otherStatement = { ...localStatement, aaguid: otherAAGUID, description: 'Other statement' };
    });

    /**
     * Initialize with a BLOB (`no: 1`) that's already stale so that the next lookup attempts a
     * refresh, and return the follow-up responses in order after that
     */
    async function initializeWithStaleBLOB(...followUps: (() => Promise<Response>)[]) {
      // Follow-ups are created lazily so a rejection isn't left unhandled while the first BLOB is
      // still being verified
      const responses = [
        () =>
          generateBLOBResponse({
            no: 1,
            nextUpdate: '2023-01-01',
            statements: [statementV1, otherStatement],
          }),
        ...followUps,
      ];
      let call = 0;
      mockFetch = stub(_fetchInternals, 'stubThis', () => responses[call++]());

      await MetadataService.initialize({ mdsServers: [mdsServerURL] });
    }

    it('should fail closed when the refresh cannot reach the server', async () => {
      await initializeWithStaleBLOB(() => Promise.reject(new Error('Network down')));

      // The previously-cached statement is not used in place of a BLOB that couldn't be refreshed
      await assertRejects(
        () => MetadataService.getStatement(refreshableAAGUID),
        Error,
        'Network down',
      );
      assertSpyCalls(mockFetch, 2);
    });

    it('should fail closed when the refreshed BLOB has an old serial', async () => {
      await initializeWithStaleBLOB(
        () => generateBLOBResponse({ no: 1, nextUpdate: '2999-01-01', statement: statementV2 }),
      );

      await assertRejects(
        () => MetadataService.getStatement(refreshableAAGUID),
        Error,
        'is not greater than previous no.',
      );
      assertSpyCalls(mockFetch, 2);
    });

    it('should try the refresh again on the next lookup after a failure', async () => {
      await initializeWithStaleBLOB(
        () => Promise.reject(new Error('Network down')),
        () => generateBLOBResponse({ no: 2, nextUpdate: '2999-01-01', statement: statementV2 }),
      );

      await assertRejects(() => MetadataService.getStatement(refreshableAAGUID));
      assertSpyCalls(mockFetch, 2);

      // No delay: the very next lookup retries, and the service isn't left stuck refreshing
      const statement = await MetadataService.getStatement(refreshableAAGUID);

      assertSpyCalls(mockFetch, 3);
      assertEquals(statement, statementV2);
    });

    it('should fail every concurrent lookup with a single failed refresh', async () => {
      // Fail after a short delay so the refresh is still in flight when every lookup arrives
      await initializeWithStaleBLOB(() =>
        new Promise<Response>((_resolve, reject) =>
          setTimeout(() => reject(new Error('Network down')), 50)
        )
      );

      const results = await Promise.allSettled([
        MetadataService.getStatement(refreshableAAGUID),
        MetadataService.getStatement(refreshableAAGUID),
        MetadataService.getStatement(otherAAGUID),
      ]);

      assertSpyCalls(mockFetch, 2);
      assertEquals(results.map(({ status }) => status), ['rejected', 'rejected', 'rejected']);
    });

    it('should evict statements the refreshed BLOB no longer includes', async () => {
      await initializeWithStaleBLOB(
        () => generateBLOBResponse({ no: 2, nextUpdate: '2999-01-01', statement: statementV2 }),
      );

      // Trigger the refresh via the AAGUID that's still present
      assertEquals(await MetadataService.getStatement(refreshableAAGUID), statementV2);

      // The server dropped this AAGUID, so it shouldn't linger in the cache
      await assertRejects(
        () => MetadataService.getStatement(otherAAGUID),
        Error,
        'No metadata statement found',
      );
    });

    it('should keep local statements when a refresh evicts statements from a server', async () => {
      const localOnlyAAGUID = '00000000-0000-0000-0000-000000000009';
      const localOnlyStatement: MetadataStatement = {
        ...localStatement,
        aaguid: localOnlyAAGUID,
      };
      mockFetch = stub(
        _fetchInternals,
        'stubThis',
        returnsNext([
          generateBLOBResponse({ no: 1, nextUpdate: '2023-01-01', statement: statementV1 }),
          generateBLOBResponse({ no: 2, nextUpdate: '2999-01-01', statement: statementV2 }),
        ]),
      );
      await MetadataService.initialize({
        mdsServers: [mdsServerURL],
        statements: [localOnlyStatement],
      });

      assertEquals(await MetadataService.getStatement(refreshableAAGUID), statementV2);
      assertSpyCalls(mockFetch, 2);
      assertEquals(await MetadataService.getStatement(localOnlyAAGUID), localOnlyStatement);
    });

    it('should discover a statement added to the server since the last refresh', async () => {
      const addedAAGUID = '00000000-0000-0000-0000-000000000008';
      const addedStatement: MetadataStatement = { ...localStatement, aaguid: addedAAGUID };
      await initializeWithStaleBLOB(
        () =>
          generateBLOBResponse({
            no: 2,
            nextUpdate: '2999-01-01',
            statements: [statementV1, addedStatement],
          }),
      );

      // The lookup for an uncached AAGUID is what triggers the refresh
      const statement = await MetadataService.getStatement(addedAAGUID);

      assertSpyCalls(mockFetch, 2);
      assertEquals(statement, addedStatement);
    });

    it('should share one refresh between concurrent lookups', async () => {
      await initializeWithStaleBLOB(
        () => generateBLOBResponse({ no: 2, nextUpdate: '2999-01-01', statement: statementV2 }),
      );

      const results = await Promise.all([
        MetadataService.getStatement(refreshableAAGUID),
        MetadataService.getStatement(refreshableAAGUID),
        MetadataService.getProviderMetadata(refreshableAAGUID),
      ]);

      assertSpyCalls(mockFetch, 2);
      assertEquals(results[0], statementV2);
      assertEquals(results[1], statementV2);
    });

    it('should still serve local statements when a server fails its initial download', async () => {
      mockFetch = stub(
        _fetchInternals,
        'stubThis',
        returnsNext([Promise.reject(new Error('Network down'))]),
      );

      await MetadataService.initialize({
        mdsServers: [mdsServerURL],
        statements: [localStatement],
      });

      // The server never provided a BLOB, so it's not tracked for refreshes and can't break lookups
      assertEquals(await MetadataService.getStatement(localStatementAAGUID), localStatement);
      assertSpyCalls(mockFetch, 1);
    });
  });

  it('should not refresh a BLOB that is still current', async () => {
    const statement: MetadataStatement = {
      ...localStatement,
      aaguid: refreshableAAGUID,
      description: 'Statement from a current BLOB',
    };

    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        generateBLOBResponse({ no: 3, nextUpdate: '2999-01-01', statement }),
      ]),
    );

    await MetadataService.initialize({ mdsServers: [mdsServerURL] });

    const returnedStatement = await MetadataService.getStatement(refreshableAAGUID);

    assertSpyCalls(mockFetch, 1);
    assertEquals(returnedStatement, statement);
  });
});

describe('Behavior: logging', () => {
  it('should use provided logger', async () => {
    const _debugSpy = spy();

    await MetadataService.initialize({
      mdsServers: [],
      statements: [],
      logger: { debug: _debugSpy },
    });

    /**
     * NOTE TO FUTURE SELF: As of June 2026 the content of the logging is less important here than
     * the fact that the service used the provided logger to communicate internal goings on.
     */
    assertSpyCallArg(_debugSpy, 0, 0, 'MetadataService is REFRESHING');
    assertSpyCallArg(_debugSpy, 1, 0, 'MetadataService is READY');
  });
});

const localStatementAAGUID = '91dfead7-959e-4475-ad26-9b0d482be089';
const localStatement: MetadataStatement = {
  legalHeader: 'https://fidoalliance.org/metadata/metadata-statement-legal-header/',
  description: 'Virtual FIDO2 EdDSA25519 SHA512 Conformance Testing CTAP2 Authenticator',
  aaguid: localStatementAAGUID,
  protocolFamily: 'fido2',
  authenticatorVersion: 2,
  upv: [
    {
      major: 1,
      minor: 0,
    },
  ],
  authenticationAlgorithms: ['ed25519_eddsa_sha512_raw'],
  publicKeyAlgAndEncodings: ['cose'],
  attestationTypes: ['basic_full', 'basic_surrogate'],
  schema: 3,
  userVerificationDetails: [
    [
      {
        userVerificationMethod: 'none',
      },
    ],
  ],
  keyProtection: ['hardware', 'secure_element'],
  matcherProtection: ['on_chip'],
  cryptoStrength: 128,
  attachmentHint: ['external', 'wired', 'wireless', 'nfc'],
  tcDisplay: [],
  attestationRootCertificates: [],
  supportedExtensions: [
    {
      id: 'hmac-secret',
      fail_if_unknown: false,
    },
  ],
  authenticatorGetInfo: {
    versions: ['U2F_V2', 'FIDO_2_0'],
    extensions: ['credProtect', 'hmac-secret'],
    aaguid: '91dfead7959e4475ad269b0d482be089',
    options: {
      plat: false,
      rk: true,
      clientPin: true,
      up: true,
      uv: true,
    },
    maxMsgSize: 1200,
  },
};

type BLOBSigner = {
  /** The trust anchor that the BLOB's leaf cert chains back to */
  rootCertPEM: string;
  /** The BLOB's leaf cert, ready to drop into a JWT header's `x5c` */
  leafCertBase64: string;
  /** The leaf cert's keys, used to sign the BLOB itself */
  leafKeys: CryptoKeyPair;
};

/**
 * A root cert, and the leaf cert it signed, for signing the MDS BLOBs generated below.
 */
let blobSigner: BLOBSigner | undefined;
/**
 * Generate a BLOB signer once, and then reuse it so that every use of `generateBLOBResponse()` in
 * here generates a BLOB that can chains back to the same trust anchor.
 */
async function getBLOBSigner(): Promise<BLOBSigner> {
  if (!blobSigner) {
    const notBefore = new Date(Date.now() - 60_000);
    const notAfter = new Date(Date.now() + 3_600_000);

    const root = await generateRootCert({
      notBefore,
      notAfter,
      name: 'CN=FAKE Metadata BLOB Root FAKE',
    });
    const leaf = await generateLeafCert({
      notBefore,
      notAfter,
      issuer: root,
      subject: 'CN=FAKE Metadata BLOB Signer FAKE',
    });

    blobSigner = {
      rootCertPEM: root.certificate.toString('pem'),
      leafCertBase64: isoBase64URL.fromBuffer(
        new Uint8Array(leaf.certificate.rawData),
        'base64',
      ),
      leafKeys: leaf.keys,
    };
  }

  return blobSigner;
}

/**
 * Generate a `Response` containing a signed, verifiable MDS BLOB with a single entry in it, so
 * that BLOB downloads can be exercised without network access
 */
async function generateBLOBResponse(opts: {
  no: number;
  nextUpdate: string;
  statement?: MetadataStatement;
  statements?: MetadataStatement[];
}): Promise<Response> {
  const { no, nextUpdate, statement, statements = statement ? [statement] : [] } = opts;

  const { leafCertBase64, leafKeys } = await getBLOBSigner();

  const header = isoBase64URL.fromUTF8String(JSON.stringify({
    typ: 'JWT',
    alg: 'ES256',
    x5c: [leafCertBase64],
  }));
  const payload = isoBase64URL.fromUTF8String(JSON.stringify({
    legalHeader: 'https://fidoalliance.org/metadata/metadata-legal-header/',
    no,
    nextUpdate,
    entries: statements.map((entryStatement) => ({
      aaguid: entryStatement.aaguid,
      metadataStatement: entryStatement,
      statusReports: [],
      timeOfLastStatusChange: '1970-01-01',
    })),
  }));

  const signatureBytes = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    leafKeys.privateKey,
    new TextEncoder().encode(`${header}.${payload}`),
  );
  const signature = isoBase64URL.fromBuffer(new Uint8Array(signatureBytes));

  const blob = `${header}.${payload}.${signature}`;

  return new Response(blob);
}
