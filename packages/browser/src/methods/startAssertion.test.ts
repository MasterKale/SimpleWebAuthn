import {
  AssertionCredential,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
} from '@simplewebauthn/typescript-types';

import { browserSupportsWebauthn } from '../helpers/browserSupportsWebauthn';
import utf8StringToBuffer from '../helpers/utf8StringToBuffer';
import bufferToBase64URLString from '../helpers/bufferToBase64URLString';

import startAssertion from './startAssertion';

jest.mock('../helpers/browserSupportsWebauthn');

const mockNavigatorGet = window.navigator.credentials.get as jest.Mock;
const mockSupportsWebauthn = browserSupportsWebauthn as jest.Mock;

const mockAuthenticatorData = 'mockAuthenticatorData';
const mockClientDataJSON = 'mockClientDataJSON';
const mockSignature = 'mockSignature';
const mockUserHandle = 'mockUserHandle';

// With ASCII challenge
const goodOpts1: PublicKeyCredentialRequestOptionsJSON = {
  challenge: bufferToBase64URLString(utf8StringToBuffer('fizz')),
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
  challenge: bufferToBase64URLString(utf8StringToBuffer('やれやれだぜ')),
  allowCredentials: [],
  timeout: 1,
};

beforeEach(() => {
  // Stub out a response so the method won't throw
  mockNavigatorGet.mockImplementation((): Promise<any> => {
    return new Promise(resolve => {
      resolve({
        response: {},
        getClientExtensionResults: () => ({}),
      });
    });
  });

  mockSupportsWebauthn.mockReturnValue(true);
});

afterEach(() => {
  mockNavigatorGet.mockReset();
  mockSupportsWebauthn.mockReset();
});

test('should convert options before passing to navigator.credentials.get(...)', async done => {
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
  await startAssertion({
    challenge: bufferToBase64URLString(utf8StringToBuffer('fizz')),
    timeout: 1,
  });

  expect(mockNavigatorGet.mock.calls[0][0].allowCredentials).toEqual(undefined);
});

test('should convert allow allowCredential to undefined when empty', async () => {
  await startAssertion({
    challenge: bufferToBase64URLString(utf8StringToBuffer('fizz')),
    timeout: 1,
    allowCredentials: [],
  });
  expect(mockNavigatorGet.mock.calls[0][0].allowCredentials).toEqual(undefined);
});

test('should return base64url-encoded response values', async done => {
  mockNavigatorGet.mockImplementation((): Promise<AssertionCredential> => {
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
  });

  const response = await startAssertion(goodOpts1);

  expect(response.rawId).toEqual('Zm9vYmFy');
  expect(response.response.authenticatorData).toEqual('bW9ja0F1dGhlbnRpY2F0b3JEYXRh');
  expect(response.response.clientDataJSON).toEqual('bW9ja0NsaWVudERhdGFKU09O');
  expect(response.response.signature).toEqual('bW9ja1NpZ25hdHVyZQ');
  expect(response.response.userHandle).toEqual('mockUserHandle');

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
  mockNavigatorGet.mockImplementation((): Promise<null> => {
    return new Promise(resolve => {
      resolve(null);
    });
  });

  await expect(startAssertion(goodOpts1)).rejects.toThrow('Assertion was not completed');

  done();
});

test('should handle UTF-8 challenges', async done => {
  await startAssertion(goodOpts2UTF8);

  const argsPublicKey = mockNavigatorGet.mock.calls[0][0].publicKey;

  expect(new Uint8Array(argsPublicKey.challenge)).toEqual(
    new Uint8Array([
      227, 130, 132, 227, 130, 140, 227, 130, 132, 227, 130, 140, 227, 129, 160, 227, 129, 156,
    ]),
  );

  done();
});

test('should send extensions to authenticator if present in options', async done => {
  const extensions: AuthenticationExtensionsClientInputs = {
    credProps: true,
    appid: 'appidHere',
    uvm: true,
    appidExclude: 'appidExcludeHere',
  };
  const optsWithExts: PublicKeyCredentialRequestOptionsJSON = {
    ...goodOpts1,
    extensions,
  };
  await startAssertion(optsWithExts);

  const argsExtensions = mockNavigatorGet.mock.calls[0][0].publicKey.extensions;

  expect(argsExtensions).toEqual(extensions);

  done();
});

test('should not set any extensions if not present in options', async done => {
  await startAssertion(goodOpts1);

  const argsExtensions = mockNavigatorGet.mock.calls[0][0].publicKey.extensions;

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
  mockNavigatorGet.mockImplementation((): Promise<any> => {
    return new Promise(resolve => {
      resolve({ response: {}, getClientExtensionResults: () => extResults });
    });
  });

  // Extensions aren't present in this object, but it doesn't matter since we're faking the response
  const response = await startAssertion(goodOpts1);

  expect(response.clientExtensionResults).toEqual(extResults);

  done();
});

test('should include extension results when no extensions specified', async done => {
  const response = await startAssertion(goodOpts1);

  expect(response.clientExtensionResults).toEqual({});

  done();
});
