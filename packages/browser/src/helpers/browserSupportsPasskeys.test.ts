/// <reference lib="DOM" />
import { assert, assertFalse } from '@std/assert';
import { returnsNext, stub } from '@std/testing/mock';
import { browserSupportsPasskeys } from './browserSupportsPasskeys.ts';
import { _getBrowserCapabilitiesInternals } from './getBrowserCapabilities.ts';

Deno.test('Returns true when passkeyPlatformAuthenticator capability is supported', async () => {
  // @ts-ignore: Setting up global state
  globalThis.PublicKeyCredential = () => {};

  const mockGetBrowserCapabilities = stub(
    _getBrowserCapabilitiesInternals,
    'stubThis',
    // @ts-ignore: Keeping tests lean
    returnsNext([{ passkeyPlatformAuthenticator: 'supported' }]),
  );

  const supported = await browserSupportsPasskeys();

  assert(supported);

  mockGetBrowserCapabilities.restore();
});

Deno.test('Returns true when userVerifyingPlatformAuthenticator capability is supported', async () => {
  // @ts-ignore: Setting up global state
  globalThis.PublicKeyCredential = () => {};

  const mockGetBrowserCapabilities = stub(
    _getBrowserCapabilitiesInternals,
    'stubThis',
    // @ts-ignore: Keeping tests lean
    returnsNext([{ userVerifyingPlatformAuthenticator: 'supported' }]),
  );

  const supported = await browserSupportsPasskeys();

  assert(supported);

  mockGetBrowserCapabilities.restore();
});

Deno.test('Returns true when hybridTransport capability is supported', async () => {
  // @ts-ignore: Setting up global state
  globalThis.PublicKeyCredential = () => {};

  const mockGetBrowserCapabilities = stub(
    _getBrowserCapabilitiesInternals,
    'stubThis',
    // @ts-ignore: Keeping tests lean
    returnsNext([{ hybridTransport: 'supported' }]),
  );

  const supported = await browserSupportsPasskeys();

  assert(supported);

  mockGetBrowserCapabilities.restore();
});

Deno.test('Returns false when no relevant capabilities are supported', async () => {
  // @ts-ignore: Setting up global state
  globalThis.PublicKeyCredential = () => {};

  const mockGetBrowserCapabilities = stub(
    _getBrowserCapabilitiesInternals,
    'stubThis',
    // @ts-ignore: Keeping tests lean
    returnsNext([{}]),
  );

  const supported = await browserSupportsPasskeys();

  assertFalse(supported);

  mockGetBrowserCapabilities.restore();
});
