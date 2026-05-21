/// <reference lib="DOM" />
import { assertEquals } from '@std/assert';
import { getBrowserCapabilities } from './getBrowserCapabilities.ts';

Deno.test('Maps raw capabilities to string values', async () => {
  // @ts-ignore: Set up PublicKeyCredential
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.getClientCapabilities = () =>
    new Promise((resolve) => {
      resolve({
        conditionalCreate: true,
        conditionalGet: true,
        hybridTransport: true,
        passkeyPlatformAuthenticator: false,
        userVerifyingPlatformAuthenticator: false,
        relatedOrigins: false,
        // These values are missing
        // signalAllAcceptedCredentials: undefined,
        // signalCurrentUserDetails: undefined,
        // signalUnknownCredential: undefined,
      });
    });

  const capabilities = await getBrowserCapabilities();

  assertEquals(
    capabilities,
    {
      conditionalCreate: 'supported',
      conditionalGet: 'supported',
      hybridTransport: 'supported',
      passkeyPlatformAuthenticator: 'unsupported',
      userVerifyingPlatformAuthenticator: 'unsupported',
      relatedOrigins: 'unsupported',
      signalAllAcceptedCredentials: 'unknown',
      signalCurrentUserDetails: 'unknown',
      signalUnknownCredential: 'unknown',
    },
  );
});

Deno.test('Works even when getClientCapabilities is missing', async () => {
  // @ts-ignore: Pretend the method doesn't exist
  globalThis.PublicKeyCredential = () => {};

  const capabilities = await getBrowserCapabilities();

  for (const [key, value] of Object.entries(capabilities)) {
    assertEquals(value, 'unknown', `capability "${key}" was not "unknown"`);
  }
});

Deno.test('Determines userVerifyingPlatformAuthenticator support via alternative means', async () => {
  // @ts-ignore: Pretend the method doesn't exist
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.getClientCapabilities = () =>
    new Promise((resolve) => {
      // Equivalent to all features being `undefined`
      resolve({});
    });
  globalThis.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;

  const capabilities = await getBrowserCapabilities();

  assertEquals(capabilities.userVerifyingPlatformAuthenticator, 'supported');
});

Deno.test('Determines conditionalGet support via alternative means', async () => {
  // @ts-ignore: Pretend the method doesn't exist
  globalThis.PublicKeyCredential = () => {};
  globalThis.PublicKeyCredential.getClientCapabilities = () =>
    new Promise((resolve) => {
      // Equivalent to all features being `undefined`
      resolve({});
    });
  globalThis.PublicKeyCredential.isConditionalMediationAvailable = async () => true;

  const capabilities = await getBrowserCapabilities();

  assertEquals(capabilities.conditionalGet, 'supported');
});
