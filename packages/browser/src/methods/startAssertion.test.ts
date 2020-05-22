import base64js from 'base64-js';

import { AssertionCredential, PublicKeyCredentialRequestOptionsJSON } from '@webauthntine/typescript-types';

import toUint8Array from '../helpers/toUint8Array';
import supportsWebauthn from '../helpers/supportsWebauthn';

import startAssertion from './startAssertion';

jest.mock('../helpers/supportsWebauthn');

const mockNavigatorGet = (window.navigator.credentials.get as jest.Mock);
const mockSupportsWebauthn = (supportsWebauthn as jest.Mock);

const mockAttestationObject = 'mockAsse';
const mockClientDataJSON = 'mockClie';
const mockSignature = 'mockSign';
const mockUserHandle = 'mockUser';

const goodOpts1: PublicKeyCredentialRequestOptionsJSON = {
  publicKey: {
    challenge: 'fizz',
    allowCredentials: [{
      id: 'credId',
      type: 'public-key',
      transports: ['nfc'],
    }],
    timeout: 1,
  },
};

beforeEach(() => {
  mockNavigatorGet.mockReset();
  mockSupportsWebauthn.mockReset();
});

test('should convert options before passing to navigator.credentials.get(...)', async (done) => {
  mockSupportsWebauthn.mockReturnValue(true);

  // Stub out a response so the method won't throw
  mockNavigatorGet.mockImplementation((): Promise<any> => {
    return new Promise((resolve) => {
      resolve({ response: {} });
    });
  });

  await startAssertion(goodOpts1);

  const argsPublicKey = mockNavigatorGet.mock.calls[0][0].publicKey;

  expect(argsPublicKey.challenge).toEqual(toUint8Array(goodOpts1.publicKey.challenge));
  expect(argsPublicKey.allowCredentials[0].id).toEqual(
    toUint8Array(goodOpts1.publicKey.allowCredentials[0].id),
  );

  done();
});

test('should return base64-encoded response values', async (done) => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorGet.mockImplementation((): Promise<AssertionCredential> => {
    return new Promise((resolve) => {
      resolve({
        id: 'foobar',
        rawId: toUint8Array('foobar'),
        response: {
          clientDataJSON: base64js.toByteArray(mockClientDataJSON),
          authenticatorData: base64js.toByteArray(mockClientDataJSON),
          signature: base64js.toByteArray(mockSignature),
          userHandle: base64js.toByteArray(mockUserHandle),
        },
        getClientExtensionResults: () => ({}),
        type: 'webauthn.get',
      });
    });
  });

  const response = await startAssertion(goodOpts1);

  expect(response).toEqual({
    base64AuthenticatorData: mockClientDataJSON,
    base64ClientDataJSON: mockClientDataJSON,
    base64Signature: mockSignature,
    base64UserHandle: mockUserHandle,
  });

  done();
})

test('should throw error if WebAuthn isn\'t supported', async (done) => {
  mockSupportsWebauthn.mockReturnValue(false);

  await expect(startAssertion(goodOpts1)).rejects.toThrow('WebAuthn is not supported in this browser');

  done();
});

test('should throw error if assertion is cancelled for some reason', async (done) => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorGet.mockImplementation((): Promise<null> => {
    return new Promise((resolve) => {
      resolve(null);
    });
  });

  await expect(startAssertion(goodOpts1)).rejects.toThrow('Assertion was not completed');

  done();
});
