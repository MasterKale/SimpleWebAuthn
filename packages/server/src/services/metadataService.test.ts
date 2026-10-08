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
import { FakeTime } from '@std/testing/time';

import { _fetchInternals } from '../helpers/fetch.ts';
import { isoBase64URL } from '../helpers/iso/index.ts';
import { generateLeafCert, generateRootCert } from '../helpers/tests/x509Utils.ts';

import { BaseMetadataService, MetadataService } from './metadataService.ts';
import { SettingsService } from './settingsService.ts';
import type { MetadataStatement } from '../metadata/mdsTypes.ts';
import type { ConvenienceMDSPayload, ProviderMetadata } from '../metadata/convenienceMDSTypes.ts';

let mockFetch: Stub;

describe('Method: initialize()', () => {
  beforeEach(() => {
    mockFetch = stub(_fetchInternals, 'stubThis');
  });

  afterEach(() => {
    mockFetch.restore();
  });

  it('should default to querying MDS v3 and convenience MDS', async () => {
    await MetadataService.initialize();

    assertSpyCalls(mockFetch, 2);
    assertSpyCallArg(mockFetch, 0, 0, 'https://mds.fidoalliance.org/');
    assertSpyCallArg(mockFetch, 1, 0, 'https://c-mds.fidoalliance.org/?localCopySerial=0');
  });

  it('should query provided MDS server URLs', async () => {
    const mdsServers = ['https://custom-mds1.com', 'https://custom-mds2.com'];

    await MetadataService.initialize({
      mdsServers,
      convenienceMDSServers: [],
    });

    assertSpyCalls(mockFetch, mdsServers.length);
    assertSpyCallArg(mockFetch, 0, 0, mdsServers[0]);
    assertSpyCallArg(mockFetch, 1, 0, mdsServers[1]);
  });

  it('should not query any servers on empty list of URLs', async () => {
    await MetadataService.initialize({ mdsServers: [], convenienceMDSServers: [] });

    assertSpyCalls(mockFetch, 0);
  });

  it('should load local statements', async () => {
    await MetadataService.initialize({
      statements: [localStatement],
    });

    const statement = await MetadataService.getStatement(localStatementAAGUID);

    assertEquals(statement, localStatement);
  });

  it('should query provided convenience MDS server URLs', async () => {
    const convenienceMDSServers = ['https://custom-cmds1.com', 'https://custom-cmds2.com'];

    await MetadataService.initialize({ mdsServers: [], convenienceMDSServers });

    assertSpyCalls(mockFetch, convenienceMDSServers.length);
    assertSpyCallArg(mockFetch, 0, 0, 'https://custom-cmds1.com/?localCopySerial=0');
    assertSpyCallArg(mockFetch, 1, 0, 'https://custom-cmds2.com/?localCopySerial=0');
  });

  it('should not query any convenience MDS servers on empty list of URLs', async () => {
    await MetadataService.initialize({ mdsServers: [], convenienceMDSServers: [] });

    assertSpyCalls(mockFetch, 0);
  });

  it('should load local convenience payloads', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: [],
      conveniencePayloads: [localConveniencePayload],
    });

    const metadata = await MetadataService.getProviderMetadata(localStatementAAGUID);

    assertEquals(metadata, localProviderMetadata);
  });

  it('should load convenience payloads without querying any servers', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: [],
      conveniencePayloads: [localConveniencePayload],
    });

    assertSpyCalls(mockFetch, 0);
  });

  it('should load metadata from multiple convenience payloads', async () => {
    const otherAAGUID = '00000000-0000-0000-0000-000000000002';
    const otherMetadata: ProviderMetadata = { friendlyNames: { en: 'Other Provider' } };

    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: [],
      conveniencePayloads: [
        localConveniencePayload,
        { no: 1, [otherAAGUID]: otherMetadata } as ConvenienceMDSPayload,
      ],
    });

    assertEquals(
      await MetadataService.getProviderMetadata(localStatementAAGUID),
      localProviderMetadata,
    );
    assertEquals(await MetadataService.getProviderMetadata(otherAAGUID), otherMetadata);
  });

  it('should load metadata from a convenience MDS server', async () => {
    mockFetch.restore();
    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        Promise.resolve(Response.json(localConveniencePayload)),
      ]),
    );

    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: ['https://custom-cmds.com'],
    });

    const metadata = await MetadataService.getProviderMetadata(localStatementAAGUID);

    assertEquals(metadata, localProviderMetadata);
  });

  it('should move on if a convenience MDS server cannot be reached', async () => {
    mockFetch.restore();
    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        Promise.reject(new Error('Network down')),
        Promise.resolve(Response.json(localConveniencePayload)),
      ]),
    );

    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: ['https://broken-cmds.com', 'https://working-cmds.com'],
    });

    const metadata = await MetadataService.getProviderMetadata(localStatementAAGUID);

    assertEquals(metadata, localProviderMetadata);
  });

  it('should use local convenience payloads as a fallback to convenience MDS servers', async () => {
    const serverOnlyAAGUID = '00000000-0000-0000-0000-000000000004';
    const serverMetadata: ProviderMetadata = { friendlyNames: { en: 'From Server' } };

    mockFetch.restore();
    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        Promise.resolve(Response.json({
          no: 1,
          [localStatementAAGUID]: serverMetadata,
          [serverOnlyAAGUID]: serverMetadata,
        })),
      ]),
    );

    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: ['https://custom-cmds.com'],
      conveniencePayloads: [
        localConveniencePayload,
        {
          no: 1,
          '00000000-0000-0000-0000-000000000005': localProviderMetadata,
        } as ConvenienceMDSPayload,
      ],
    });

    // The server wins on a shared AAGUID
    assertEquals(
      await MetadataService.getProviderMetadata(localStatementAAGUID),
      serverMetadata,
    );
    assertEquals(await MetadataService.getProviderMetadata(serverOnlyAAGUID), serverMetadata);
    // The local payload still fills in AAGUIDs the server doesn't know about
    assertEquals(
      await MetadataService.getProviderMetadata('00000000-0000-0000-0000-000000000005'),
      localProviderMetadata,
    );
  });

  it('should cache convenience metadata from local statements', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: [],
      statements: [{ ...localStatement, friendlyNames: { en: 'From Statement' } }],
    });

    const metadata = await MetadataService.getProviderMetadata(localStatementAAGUID);

    assertEquals(metadata?.friendlyNames, { en: 'From Statement' });
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
  const cmdsURL = 'https://cmds.example.com/';
  const aaguid = '00000000-0000-0000-0000-000000000003';
  const originalMetadata: ProviderMetadata = { friendlyNames: { en: 'Original Name' } };
  const updatedMetadata: ProviderMetadata = { friendlyNames: { en: 'Updated Name' } };
  const eightDaysMS = 1000 * 60 * 60 * 24 * 8;
  let mockFetch: Stub;

  beforeEach(() => {
    mockFetch = stub(_fetchInternals, 'stubThis');
  });

  afterEach(() => {
    mockFetch.restore();
  });

  /** Initialize with a convenience MDS server that responds with `no: 1` and `originalMetadata` */
  async function initializeWithServer(...followUps: Promise<Response>[]) {
    mockFetch.restore();
    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([
        Promise.resolve(Response.json({ no: 1, [aaguid]: originalMetadata })),
        ...followUps,
      ]),
    );

    await MetadataService.initialize({ mdsServers: [], convenienceMDSServers: [cmdsURL] });
  }

  it('should return undefined if service not initialized', async () => {
    const service = new BaseMetadataService();
    const metadata = await service.getProviderMetadata('not-a-real-aaguid');

    assertEquals(metadata, undefined);
  });

  it('should return undefined if aaguid is undefined', async () => {
    // @ts-ignore: intentionally passing a bad value
    const metadata = await MetadataService.getProviderMetadata(undefined);

    assertEquals(metadata, undefined);
  });

  it('should return undefined for an AAGUID with no metadata', async () => {
    await MetadataService.initialize({ mdsServers: [], convenienceMDSServers: [] });

    const metadata = await MetadataService.getProviderMetadata('not-a-real-aaguid');

    assertEquals(metadata, undefined);
  });

  it('should accept the AAGUID as a Uint8Array', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: [],
      conveniencePayloads: [localConveniencePayload],
    });

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

    assertEquals(metadata, localProviderMetadata);
  });

  it('should not refresh metadata from a current convenience MDS', async () => {
    await initializeWithServer();

    const metadata = await MetadataService.getProviderMetadata(aaguid);

    assertSpyCalls(mockFetch, 1);
    assertEquals(metadata, originalMetadata);
  });

  it('should return up-to-date metadata after refreshing stale convenience metadata', async () => {
    using _fakedNow = new FakeTime();
    await initializeWithServer(
      Promise.resolve(Response.json({ no: 2, [aaguid]: updatedMetadata })),
    );

    _fakedNow.tick(eightDaysMS);

    const metadata = await MetadataService.getProviderMetadata(aaguid);

    assertSpyCalls(mockFetch, 2);
    // Confirm a check for an updated payload using the old serial
    assertSpyCallArg(mockFetch, 1, 0, `${cmdsURL}?localCopySerial=1`);
    // Getting the updated metadata means the internal cache was refreshed correctly
    assertEquals(metadata, updatedMetadata);
  });

  it('should keep cached metadata when the stale convenience MDS responds with 304', async () => {
    using _fakedNow = new FakeTime();
    await initializeWithServer(Promise.resolve(new Response(null, { status: 304 })));

    _fakedNow.tick(eightDaysMS);

    const metadata = await MetadataService.getProviderMetadata(aaguid);

    assertSpyCalls(mockFetch, 2);
    assertEquals(metadata, originalMetadata);
  });

  it('should keep cached metadata when the stale convenience MDS responds with 429', async () => {
    using _fakedNow = new FakeTime();
    await initializeWithServer(Promise.resolve(new Response(null, { status: 429 })));

    _fakedNow.tick(eightDaysMS);

    const metadata = await MetadataService.getProviderMetadata(aaguid);

    assertSpyCalls(mockFetch, 2);
    assertEquals(metadata, originalMetadata);
  });

  it('should not refresh metadata from local payloads', async () => {
    using _fakedNow = new FakeTime();
    await MetadataService.initialize({
      mdsServers: [],
      convenienceMDSServers: [],
      conveniencePayloads: [localConveniencePayload],
    });

    _fakedNow.tick(eightDaysMS);

    const metadata = await MetadataService.getProviderMetadata(localStatementAAGUID);

    assertSpyCalls(mockFetch, 0);
    assertEquals(metadata, localProviderMetadata);
  });

  it('should return the service to a ready state if a refresh fails', async () => {
    using _fakedNow = new FakeTime();
    await initializeWithServer(Promise.reject(new Error('Network down')));

    _fakedNow.tick(eightDaysMS);

    await assertRejects(() => MetadataService.getProviderMetadata(aaguid));

    // A subsequent call shouldn't hang waiting for a ready state
    mockFetch.restore();
    mockFetch = stub(
      _fetchInternals,
      'stubThis',
      returnsNext([Promise.resolve(new Response(null, { status: 304 }))]),
    );
    const metadata = await MetadataService.getProviderMetadata(aaguid);

    assertEquals(metadata, originalMetadata);
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

    await MetadataService.initialize({ mdsServers: [mdsServerURL], convenienceMDSServers: [] });

    assertSpyCalls(mockFetch, 1);

    const statement = await MetadataService.getStatement(refreshableAAGUID);

    // The stale BLOB should have been re-downloaded...
    assertSpyCalls(mockFetch, 2);
    assertSpyCallArg(mockFetch, 1, 0, mdsServerURL);
    // ...and the statement from the newer BLOB returned
    assertEquals(statement, freshStatement);
    assertNotEquals(statement, staleStatement);
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

    await MetadataService.initialize({ mdsServers: [mdsServerURL], convenienceMDSServers: [] });

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
const localProviderMetadata: ProviderMetadata = {
  friendlyNames: { en: 'Local Provider', fr: 'Fournisseur local' },
};
const localConveniencePayload: ConvenienceMDSPayload = {
  no: 1,
  [localStatementAAGUID]: localProviderMetadata,
} as ConvenienceMDSPayload;
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
  statement: MetadataStatement;
}): Promise<Response> {
  const { no, nextUpdate, statement } = opts;

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
    entries: [
      {
        aaguid: statement.aaguid,
        metadataStatement: statement,
        statusReports: [],
        timeOfLastStatusChange: '1970-01-01',
      },
    ],
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
