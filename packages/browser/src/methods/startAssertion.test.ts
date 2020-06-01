import base64js from 'base64-js';

import {
  AssertionCredential,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/typescript-types';

import toUint8Array from '../helpers/toUint8Array';
import supportsWebauthn from '../helpers/supportsWebauthn';
import toBase64String from '../helpers/toBase64String';

import startAssertion from './startAssertion';

jest.mock('../helpers/supportsWebauthn');

const mockNavigatorGet = window.navigator.credentials.get as jest.Mock;
const mockSupportsWebauthn = supportsWebauthn as jest.Mock;

const mockAuthenticatorData = toBase64String(toUint8Array('mockAuthenticatorData'));
const mockClientDataJSON = toBase64String(toUint8Array('mockClientDataJSON'));
const mockSignature = toBase64String(toUint8Array('mockSignature'));
const mockUserHandle = toBase64String(toUint8Array('mockUserHandle'));

const goodOpts1: PublicKeyCredentialRequestOptionsJSON = {
  challenge: 'fizz',
  allowCredentials: [
    {
      id: 'abcdefgfdnsdfunguisdfgs',
      type: 'public-key',
      transports: ['nfc'],
    },
  ],
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
        resolve({ response: {} });
      });
    },
  );

  await startAssertion(goodOpts1);

  const argsPublicKey = mockNavigatorGet.mock.calls[0][0].publicKey;
  const credId = base64js.fromByteArray(argsPublicKey.allowCredentials[0].id);

  expect(argsPublicKey.challenge).toEqual(toUint8Array(goodOpts1.challenge));
  // Make sure the credential ID is a proper base64 with a length that's a multiple of 4
  expect(credId.length % 4).toEqual(0);

  done();
});

test('should return base64-encoded response values', async done => {
  mockSupportsWebauthn.mockReturnValue(true);

  mockNavigatorGet.mockImplementation(
    (): Promise<AssertionCredential> => {
      return new Promise(resolve => {
        resolve({
          id: 'foobar',
          rawId: toUint8Array('foobar'),
          response: {
            authenticatorData: base64js.toByteArray(mockAuthenticatorData),
            clientDataJSON: base64js.toByteArray(mockClientDataJSON),
            signature: base64js.toByteArray(mockSignature),
            userHandle: base64js.toByteArray(mockUserHandle),
          },
          getClientExtensionResults: () => ({}),
          type: 'webauthn.get',
        });
      });
    },
  );

  const response = await startAssertion(goodOpts1);

  expect(response.rawId).toEqual('Zm9vYmFy');
  expect(response.response.authenticatorData).toEqual(mockAuthenticatorData);
  expect(response.response.clientDataJSON).toEqual(mockClientDataJSON);
  expect(response.response.signature).toEqual(mockSignature);
  expect(response.response.userHandle).toEqual(mockUserHandle);

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
