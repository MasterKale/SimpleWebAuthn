import { assertEquals, assertRejects } from '@std/assert';
import { afterEach, beforeEach, describe, it } from '@std/testing/bdd';
import { assertSpyCallArg, assertSpyCalls, type Stub, stub } from '@std/testing/mock';
import { FakeTime } from '@std/testing/time';

import { _fetchInternals } from '../helpers/fetch.ts';

import { BaseMetadataService, MetadataService } from './metadataService.ts';
import type { MetadataStatement } from '../metadata/mdsTypes.ts';
import { blob as testBlob, blobRootCert as testBlobRootCert } from '../metadata/verifyJWT.test.ts';
import { SettingsService } from './settingsService.ts';
import { GlobalSign_Root_CA_R3 } from './defaultRootCerts/mds.ts';

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

  it('should load local MDS blob', async () => {
    const fakedNow = new FakeTime(new Date('2026-03-03T00:00:00.000Z'));

    SettingsService.setRootCertificates({ identifier: 'mds', certificates: [testBlobRootCert] });

    await MetadataService.initialize({ mdsServers: [], mdsBlobs: [testBlob] });

    // @ts-ignore: Quick and dirty check that all statements loaded
    assertEquals(Object.keys(MetadataService.statementCache).length, 100);

    // Reset default MDS root cert
    SettingsService.setRootCertificates({
      identifier: 'mds',
      certificates: [GlobalSign_Root_CA_R3],
    });

    fakedNow.restore();
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
