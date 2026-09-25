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
    assertSpyCallArg(mockFetch, 0, 0, 'https://mds.fidoalliance.org/');
  });

  it('should query provided MDS server URLs', async () => {
    const mdsServers = ['https://custom-mds1.com', 'https://custom-mds2.com'];

    await MetadataService.initialize({
      mdsServers,
    });

    assertSpyCalls(mockFetch, mdsServers.length);
    assertSpyCallArg(mockFetch, 0, 0, mdsServers[0]);
    assertSpyCallArg(mockFetch, 1, 0, mdsServers[1]);
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
