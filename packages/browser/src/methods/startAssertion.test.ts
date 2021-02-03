import {
  AssertionCredential,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/typescript-types';

import supportsWebauthn from '../helpers/supportsWebauthn';
import bufferToBase64URLString from '../helpers/bufferToBase64URLString';

import startAssertion from './startAssertion';

jest.mock('../helpers/supportsWebauthn');

const mockNavigatorGet = window.navigator.credentials.get as jest.Mock;
const mockSupportsWebauthn = supportsWebauthn as jest.Mock;

const mockAuthenticatorData = 'mockAuthenticatorData';
const mockClientDataJSON = 'mockClientDataJSON';
const mockSignature = 'mockSignature';
const mockUserHandle = 'mockUserHandle';

// With ASCII challenge
const goodOpts1: PublicKeyCredentialRequestOptionsJSON = {
  challenge: bufferToBase64URLString(Buffer.from('fizz', 'ascii')),
  allowCredentials: [
    {
      id: 'C0VGlvYFratUdAV1iCw-ULpUW8E-exHPXQChBfyVeJZCMfjMFcwDmOFgoMUz39LoMtCJUBW8WPlLkGT6q8qTCg',
      type: 'public-key',
      transports: ['nfc'],
    },
  ],
  timeout: 1,
};

// With UTF-8 challenge
const goodOpts2UTF8: PublicKeyCredentialRequestOptionsJSON = {
  challenge: bufferToBase64URLString(Buffer.from('やれやれだぜ', 'utf-8')),
  allowCredentials: [],
  timeout: 1,
};

beforeEach(() => {
  mockNavigatorGet.mockReset();
  mockSupportsWebauthn.mockReset();
});

test('should convert options before passing to navigator.credentials.get(...)', async done => {
  mockSupportsWebauthn.mockReturnValue(true);

  // Stub out a response so the method won't throw
  mockNavigatorGet.mockImplementation(
    (): Promise<any> => {
      return new Promise(resolve => {
        resolve({
          response: {},
          getClientExtensionResults: () => ({}),
        });
      });
    },
  );

  await startAssertion(goodOpts1);

  const argsPublicKey = mockNavigatorGet.mock.calls[0][0].publicKey;
  const credId = argsPublicKey.allowCredentials[0].id;

  expect(new Uint8Array(argsPublicKey.challenge)).toEqual(new Uint8Array([102, 105, 122, 122]));
  // Make sure the credential ID is an ArrayBuffer with a length of 64
  expect(credId instanceof ArrayBuffer).toEqual(true);
  expect(credId.byteLength).toEqual(64);

  done();
});

test('should support optional allowCredential', async () => {
  mockSupportsWebauthn.mockReturnValue(true);

  // Stub out a response so the method won't throw
  mockNavigatorGet.mockImplementation(
    (): Promise<any> => {
      return new Promise(resolve => {
        resolve({
          response: {},
          getClientExtensionResults: () => ({}),
        });
      });
    },
  );

  await startAssertion({
    challenge: bufferToBase64URLString(Buffer.from('fizz', 'ascii')),
    timeout: 1,
  });

  expect(mockNavigatorGet.mock.calls[0][0].allowCredentials).toEqual(undefined);
});

test('should convert allow allowCredential to undefined when empty', async () => {
  mockSupportsWebauthn.mockReturnValue(true);

  // Stub out a response so the method won't throw
  mockNavigatorGet.mockImplementation(
    (): Promise<any> => {
      return new Promise(resolve => {
        resolve({
          response: {},
          getClientExtensionResults: () => ({}),
        });
      });
    },
  );

  await startAssertion({
    challenge: bufferToBase64URLString(Buffer.from('fizz', 'ascii')),
    timeout: 1,
    allowCredentials: [],
  });
  expect(mockNavigatorGet.mock.calls[0][0].allowCredentials).toEqual(undefined);
});

test('should return base64url-encoded response values', async done => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorGet.mockImplementation(
    (): Promise<AssertionCredential> => {
      return new Promise(resolve => {
        resolve({
          id: 'foobar',
          rawId: Buffer.from('foobar', 'ascii'),
          response: {
            authenticatorData: Buffer.from(mockAuthenticatorData, 'ascii'),
            clientDataJSON: Buffer.from(mockClientDataJSON, 'ascii'),
            signature: Buffer.from(mockSignature, 'ascii'),
            userHandle: Buffer.from(mockUserHandle, 'ascii'),
          },
          getClientExtensionResults: () => ({}),
          type: 'webauthn.get',
        });
      });
    },
  );

  const response = await startAssertion(goodOpts1);

  expect(response.rawId).toEqual('Zm9vYmFy');
  expect(response.response.authenticatorData).toEqual('bW9ja0F1dGhlbnRpY2F0b3JEYXRh');
  expect(response.response.clientDataJSON).toEqual('bW9ja0NsaWVudERhdGFKU09O');
  expect(response.response.signature).toEqual('bW9ja1NpZ25hdHVyZQ');
  expect(response.response.userHandle).toEqual('bW9ja1VzZXJIYW5kbGU');

  done();
});

test("should throw error if WebAuthn isn't supported", async done => {
  mockSupportsWebauthn.mockReturnValue(false);

  await expect(startAssertion(goodOpts1)).rejects.toThrow(
    'WebAuthn is not supported in this browser',
  );

  done();
});

test('should throw error if assertion is cancelled for some reason', async done => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorGet.mockImplementation(
    (): Promise<null> => {
      return new Promise(resolve => {
        resolve(null);
      });
    },
  );

  await expect(startAssertion(goodOpts1)).rejects.toThrow('Assertion was not completed');

  done();
});

test('should handle UTF-8 challenges', async done => {
  mockSupportsWebauthn.mockReturnValue(true);

  // Stub out a response so the method won't throw
  mockNavigatorGet.mockImplementation(
    (): Promise<any> => {
      return new Promise(resolve => {
        resolve({
          response: {},
          getClientExtensionResults: () => ({}),
        });
      });
    },
  );

  await startAssertion(goodOpts2UTF8);

  const argsPublicKey = mockNavigatorGet.mock.calls[0][0].publicKey;

  expect(new Uint8Array(argsPublicKey.challenge)).toEqual(
    new Uint8Array([
      227,
      130,
      132,
      227,
      130,
      140,
      227,
      130,
      132,
      227,
      130,
      140,
      227,
      129,
      160,
      227,
      129,
      156,
    ]),
  );

  done();
});
