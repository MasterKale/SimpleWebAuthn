jest.mock('cross-fetch');
import fetch from 'cross-fetch';

import { MetadataService, BaseMetadataService } from './metadataService';
import type { MetadataStatement } from '../metadata/mdsTypes';

const _fetch = fetch as unknown as jest.Mock;

describe('Method: initialize()', () => {
  beforeEach(() => {
    _fetch.mockReset();
  });

  test('should default to querying MDS v3', async () => {
    await MetadataService.initialize();

    expect(_fetch).toHaveBeenCalledTimes(1);
    expect(_fetch).toHaveBeenCalledWith('https://mds.fidoalliance.org/');
  });

  test('should query provided MDS server URLs', async () => {
    const mdsServers = ['https://custom-mds1.com', 'https://custom-mds2.com'];

    await MetadataService.initialize({
      mdsServers,
    });

    expect(_fetch).toHaveBeenCalledTimes(mdsServers.length);
    expect(_fetch).toHaveBeenNthCalledWith(1, mdsServers[0]);
    expect(_fetch).toHaveBeenNthCalledWith(2, mdsServers[1]);
  });

  test('should not query any servers on empty list of URLs', async () => {
    await MetadataService.initialize({ mdsServers: [] });

    expect(_fetch).not.toHaveBeenCalled();
  });

  test('should load local statements', async () => {
    await MetadataService.initialize({
      statements: [localStatement],
    });

    const statement = await MetadataService.getStatement(localStatementAAGUID);

    expect(statement).toEqual(localStatement);
  });
});

describe('Method: getStatement()', () => {
  test('should return undefined if service not initialized', async () => {
    // For lack of a way to "uninitialize" the singleton, create a new instance
    const service = new BaseMetadataService();
    const statement = await service.getStatement('not-a-real-aaguid');

    expect(statement).toBeUndefined();
  });

  test('should return undefined if aaguid is undefined', async () => {
    // TypeScript will prevent you from passing `undefined`, but JS won't so test it
    // @ts-ignore
    const statement = await MetadataService.getStatement(undefined);

    expect(statement).toBeUndefined();
  });

  test('should throw after initialization on AAGUID with no statement', async () => {
    // Require the `catch` to be evaluated
    expect.assertions(1);

    await MetadataService.initialize({
      mdsServers: [],
      statements: [],
    });

    try {
      await MetadataService.getStatement('not-a-real-aaguid');
    } catch (err) {
      expect(err).not.toBeUndefined();
    }
  });

  test('should return undefined after initialization on AAGUID with no statement and verificationMode is "permissive"', async () => {
    await MetadataService.initialize({
      mdsServers: [],
      statements: [],
      verificationMode: 'permissive',
    });

    const statement = await MetadataService.getStatement('not-a-real-aaguid');

    expect(statement).toBeUndefined();
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
