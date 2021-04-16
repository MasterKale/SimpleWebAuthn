import {
  AttestationCredential,
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/typescript-types';

import stringToArrayBuffer from '../helpers/stringToArrayBuffer';
import supportsWebauthn from '../helpers/supportsWebauthn';
import bufferToBase64URLString from '../helpers/bufferToBase64URLString';

import startAttestation from './startAttestation';

jest.mock('../helpers/supportsWebauthn');

const mockNavigatorCreate = window.navigator.credentials.create as jest.Mock;
const mockSupportsWebauthn = supportsWebauthn as jest.Mock;

const mockAttestationObject = 'mockAtte';
const mockClientDataJSON = 'mockClie';

const goodOpts1: PublicKeyCredentialCreationOptionsJSON = {
  challenge: bufferToBase64URLString(stringToArrayBuffer('fizz')),
  attestation: 'direct',
  pubKeyCredParams: [
    {
      alg: -7,
      type: 'public-key',
    },
  ],
  rp: {
    id: '1234',
    name: 'simplewebauthn',
  },
  user: {
    id: '5678',
    displayName: 'username',
    name: 'username',
  },
  timeout: 1,
  excludeCredentials: [
    {
      id: 'C0VGlvYFratUdAV1iCw-ULpUW8E-exHPXQChBfyVeJZCMfjMFcwDmOFgoMUz39LoMtCJUBW8WPlLkGT6q8qTCg',
      type: 'public-key',
      transports: ['internal'],
    },
  ],
};

beforeEach(() => {
  // Stub out a response so the method won't throw
  mockNavigatorCreate.mockImplementation(
    (): Promise<any> => {
      return new Promise(resolve => {
        resolve({ response: {}, getClientExtensionResults: () => ({}) });
      });
    },
  );

  mockSupportsWebauthn.mockReturnValue(true);
});

afterEach(() => {
  mockNavigatorCreate.mockReset();
  mockSupportsWebauthn.mockReset();
});

test('should convert options before passing to navigator.credentials.create(...)', async done => {
  await startAttestation(goodOpts1);

  const argsPublicKey = mockNavigatorCreate.mock.calls[0][0].publicKey;
  const credId = argsPublicKey.excludeCredentials[0].id;

  // Make sure challenge and user.id are converted to Buffers
  expect(new Uint8Array(argsPublicKey.challenge)).toEqual(new Uint8Array([102, 105, 122, 122]));
  expect(new Uint8Array(argsPublicKey.user.id)).toEqual(new Uint8Array([53, 54, 55, 56]));

  // Confirm construction of excludeCredentials array
  expect(credId instanceof ArrayBuffer).toEqual(true);
  expect(credId.byteLength).toEqual(64);
  expect(argsPublicKey.excludeCredentials[0].type).toEqual('public-key');
  expect(argsPublicKey.excludeCredentials[0].transports).toEqual(['internal']);

  done();
});

test('should return base64url-encoded response values', async done => {
  mockNavigatorCreate.mockImplementation(
    (): Promise<AttestationCredential> => {
      return new Promise(resolve => {
        resolve({
          id: 'foobar',
          rawId: stringToArrayBuffer('foobar'),
          response: {
            attestationObject: Buffer.from(mockAttestationObject, 'ascii'),
            clientDataJSON: Buffer.from(mockClientDataJSON, 'ascii'),
          },
          getClientExtensionResults: () => ({}),
          type: 'webauthn.create',
        });
      });
    },
  );

  const response = await startAttestation(goodOpts1);

  expect(response.rawId).toEqual('Zm9vYmFy');
  expect(response.response.attestationObject).toEqual('bW9ja0F0dGU');
  expect(response.response.clientDataJSON).toEqual('bW9ja0NsaWU');

  done();
});

test("should throw error if WebAuthn isn't supported", async done => {
  mockSupportsWebauthn.mockReturnValue(false);

  await expect(startAttestation(goodOpts1)).rejects.toThrow(
    'WebAuthn is not supported in this browser',
  );

  done();
});

test('should throw error if attestation is cancelled for some reason', async done => {
  mockNavigatorCreate.mockImplementation(
    (): Promise<null> => {
      return new Promise(resolve => {
        resolve(null);
      });
    },
  );

  await expect(startAttestation(goodOpts1)).rejects.toThrow('Attestation was not completed');

  done();
});

test('should send extensions to authenticator if present in options', async done => {
  const extensions: AuthenticationExtensionsClientInputs = {
    credProps: true,
    appid: 'appidHere',
    uvm: true,
    appidExclude: 'appidExcludeHere',
  };
  const optsWithExts: PublicKeyCredentialCreationOptionsJSON = {
    ...goodOpts1,
    extensions,
  };
  await startAttestation(optsWithExts);

  const argsExtensions = mockNavigatorCreate.mock.calls[0][0].publicKey.extensions;

  expect(argsExtensions).toEqual(extensions);

  done();
});

test('should not set any extensions if not present in options', async done => {
  await startAttestation(goodOpts1);

  const argsExtensions = mockNavigatorCreate.mock.calls[0][0].publicKey.extensions;

  expect(argsExtensions).toEqual(undefined);

  done();
});

test('should include extension results', async done => {
  const extResults: AuthenticationExtensionsClientOutputs = {
    appid: true,
    credProps: {
      rk: true,
    },
  };

  // Mock extension return values from authenticator
  mockNavigatorCreate.mockImplementation(
    (): Promise<any> => {
      return new Promise(resolve => {
        resolve({ response: {}, getClientExtensionResults: () => extResults });
      });
    },
  );

  // Extensions aren't present in this object, but it doesn't matter since we're faking the response
  const response = await startAttestation(goodOpts1);

  expect(response.clientExtensionResults).toEqual(extResults);

  done();
});

test('should include extension results when no extensions specified', async done => {
  const response = await startAttestation(goodOpts1);

  expect(response.clientExtensionResults).toEqual({});

  done();
});
