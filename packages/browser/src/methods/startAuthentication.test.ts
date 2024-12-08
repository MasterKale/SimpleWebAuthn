/// <reference lib="DOM" />
import {
  assert,
  assertEquals,
  assertExists,
  assertInstanceOf,
  assertRejects,
  assertStringIncludes,
} from '@std/assert';
import { assertSpyCalls, type Spy, spy } from '@std/testing/mock';
import { afterEach, beforeEach, describe, it } from '@std/testing/bdd';
import { JSDOM } from 'jsdom';
import type {
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  PublicKeyCredentialRequestOptionsJSON,
} from '../types/index.ts';

import { _browserSupportsWebAuthnInternals } from '../helpers/browserSupportsWebAuthn.ts';
import { _browserSupportsWebAuthnAutofillInternals } from '../helpers/browserSupportsWebAuthnAutofill.ts';
import { bufferToBase64URLString } from '../helpers/bufferToBase64URLString.ts';
import { WebAuthnError } from '../helpers/webAuthnError.ts';
import { generateCustomError } from '../helpers/__jest__/generateCustomError.ts';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService.ts';

import { startAuthentication } from './startAuthentication.ts';

// With ASCII challenge
const goodOpts1: PublicKeyCredentialRequestOptionsJSON = {
  rpId: 'example.com',
  challenge: '1T6uHri4OAQ',
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
  challenge: bufferToBase64URLString(new TextEncoder().encode('やれやれだぜ')),
  allowCredentials: [],
  timeout: 1,
};

const defaultGetResponse = async (...args: any[]) => ({
  response: {},
  getClientExtensionResults: () => ({}),
});

describe('Method: startAuthentication()', () => {
  let getSpy: Spy;

  beforeEach(() => {
    // Stub out a response so the method won't throw
    getSpy = spy(defaultGetResponse);
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials = { get: getSpy };

    // Assume WebAuthn is available
    _browserSupportsWebAuthnInternals.stubThis = () => true;
    // Assume conditional UI is supported
    _browserSupportsWebAuthnAutofillInternals.stubThis = async () => true;
  });

  afterEach(() => {
    // Reset the abort service so we get an accurate call count
    WebAuthnAbortService.cancelCeremony();
  });

  it('should convert options before passing to navigator.credentials.get(...)', async () => {
    await startAuthentication({ optionsJSON: goodOpts1 });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;
    const credId = argsPublicKey.allowCredentials?.[0].id;

    assertEquals(
      new Uint8Array(argsPublicKey.challenge as ArrayBuffer),
      new Uint8Array([213, 62, 174, 30, 184, 184, 56, 4]),
    );
    // Make sure the credential ID is an ArrayBuffer with a length of 64
    assertInstanceOf(credId, ArrayBuffer);
    assertEquals(credId.byteLength, 64);
  });

  it('should support optional allowCredential', async () => {
    await startAuthentication({
      optionsJSON: {
        challenge: '1T6uHri4OAQ',
        timeout: 1,
      },
    });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;

    assertEquals(argsPublicKey.allowCredentials, undefined);
  });

  it('should convert allow allowCredential to undefined when empty', async () => {
    await startAuthentication({
      optionsJSON: {
        challenge: '1T6uHri4OAQ',
        timeout: 1,
        allowCredentials: [],
      },
    });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;

    assertEquals(argsPublicKey.allowCredentials, undefined);
  });

  it('should return base64url-encoded response values', async () => {
    globalThis.navigator.credentials.get = async () => ({
      id: 'foobar',
      rawId: new Uint8Array([0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72]),
      response: {
        authenticatorData: new Uint8Array([1, 2, 3, 4]),
        clientDataJSON: new Uint8Array([5, 6, 7, 8]),
        signature: new Uint8Array([9, 0, 1, 2]),
        userHandle: new Uint8Array([3, 4, 5, 6]),
      },
      getClientExtensionResults: () => ({}),
      type: 'public-key',
      authenticatorAttachment: '',
    });

    const response = await startAuthentication({ optionsJSON: goodOpts1 });

    assertEquals(response.rawId, 'Zm9vYmFy');
    assertEquals(response.response.authenticatorData, 'AQIDBA');
    assertEquals(response.response.clientDataJSON, 'BQYHCA');
    assertEquals(response.response.signature, 'CQABAg');
    assertEquals(response.response.userHandle, 'AwQFBg');
  });

  it("should throw error if WebAuthn isn't supported", async () => {
    _browserSupportsWebAuthnInternals.stubThis = () => false;

    await assertRejects(
      () => startAuthentication({ optionsJSON: goodOpts1 }),
      Error,
      'WebAuthn is not supported in this browser',
    );
  });

  it('should throw error if assertion is cancelled for some reason', async () => {
    globalThis.navigator.credentials.get = async () => null;

    await assertRejects(
      () => startAuthentication({ optionsJSON: goodOpts1 }),
      Error,
      'Authentication was not completed',
    );
  });

  it('should handle UTF-8 challenges', async () => {
    await startAuthentication({ optionsJSON: goodOpts2UTF8 });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;

    assertEquals(
      new Uint8Array(argsPublicKey.challenge as ArrayBuffer),
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
  });

  it('should send extensions to authenticator if present in options', async () => {
    const extensions: AuthenticationExtensionsClientInputs = {
      credProps: true,
      appid: 'appidHere',
      // @ts-ignore: Send arbitrary extensions
      uvm: true,
      // @ts-ignore: Send arbitrary extensions
      appidExclude: 'appidExcludeHere',
    };
    const optsWithExts: PublicKeyCredentialRequestOptionsJSON = {
      ...goodOpts1,
      extensions,
    };
    await startAuthentication({ optionsJSON: optsWithExts });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;
    const argsExtensions = argsPublicKey.extensions;

    assertEquals(argsExtensions, extensions);
  });

  it('should not set any extensions if not present in options', async () => {
    await startAuthentication({ optionsJSON: goodOpts1 });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;
    const argsExtensions = argsPublicKey.extensions;

    assertEquals(argsExtensions, undefined);
  });

  it('should include extension results', async () => {
    const extResults: AuthenticationExtensionsClientOutputs = {
      appid: true,
      credProps: {
        rk: true,
      },
    };

    // Mock extension return values from authenticator
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.get = async () => ({
      response: {},
      getClientExtensionResults: () => extResults,
    });

    // Extensions aren't present in this object, but it doesn't matter since we're faking the response
    const response = await startAuthentication({ optionsJSON: goodOpts1 });

    assertEquals(response.clientExtensionResults, extResults);
  });

  it('should include extension results when no extensions specified', async () => {
    const response = await startAuthentication({ optionsJSON: goodOpts1 });

    assertEquals(response.clientExtensionResults, {});
  });

  it('should support "cable" transport', async () => {
    const opts: PublicKeyCredentialRequestOptionsJSON = {
      ...goodOpts1,
      allowCredentials: [
        {
          ...goodOpts1.allowCredentials![0],
          transports: ['cable'],
        },
      ],
    };

    await startAuthentication({ optionsJSON: opts });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;

    assertEquals(argsPublicKey.allowCredentials?.[0]?.transports?.[0], 'cable');
  });

  it('should cancel an existing call when executed again', async () => {
    const abortSpy = spy(AbortController.prototype, 'abort');

    // Fire off a request and immediately attempt a second one
    startAuthentication({ optionsJSON: goodOpts1 });
    await startAuthentication({ optionsJSON: goodOpts1 });
    assertSpyCalls(abortSpy, 1);
  });

  it('should set up autofill a.k.a. Conditional UI', async () => {
    const opts: PublicKeyCredentialRequestOptionsJSON = {
      ...goodOpts1,
      allowCredentials: [
        {
          ...goodOpts1.allowCredentials![0],
          transports: ['cable'],
        },
      ],
    };

    // Prepare a simple HTML doc
    const dom = new JSDOM(`
      <form>
        <label for="username">Username</label>
        <input type="text" name="username" autocomplete="username webauthn" />
        <button type="submit">Submit</button>
      </form>
    `);
    globalThis.document = dom.window.document;

    // @ts-ignore: Pretend this is a browser that
    globalThis.PublicKeyCredential = () => {};
    _browserSupportsWebAuthnAutofillInternals.stubThis = async () => true;

    await startAuthentication({ optionsJSON: opts, useBrowserAutofill: true });

    const args = getSpy.calls.at(0)?.args[0] as CredentialRequestOptions;
    const argsPublicKey = args.publicKey!;

    // The most important bit
    assertEquals(args.mediation, 'conditional');
    // The latest version of https://github.com/w3c/webauthn/pull/1576 says allowCredentials should
    // be an "empty list", as opposed to being undefined
    assertExists(argsPublicKey.allowCredentials);
    assertEquals(argsPublicKey.allowCredentials.length, 0);

    // @ts-ignore: Cleanup
    delete globalThis.PublicKeyCredential;
    // @ts-ignore: Cleanup
    delete globalThis.document;
  });

  it('should set up conditional UI if "webauthn" is the only autocomplete token', async () => {
    /**
     * According to WHATWG "webauthn" can be the only token in the autocomplete attribute:
     * https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill-detail-tokens
     */
    const dom = new JSDOM(`
      <form>
        <label for="username">Username</label>
        <input type="text" name="username" autocomplete="webauthn" />
        <button type="submit">Submit</button>
      </form>
    `);
    globalThis.document = dom.window.document;

    // We just want to ensure that `startAuthentication()` doesn't error out here
    const resp = await startAuthentication({ optionsJSON: goodOpts1, useBrowserAutofill: true });
    assert(resp);

    // @ts-ignore: Cleanup
    delete globalThis.document;
  });

  it('should throw error if autofill not supported', async () => {
    _browserSupportsWebAuthnAutofillInternals.stubThis = async () => false;

    await assertRejects(
      () => startAuthentication({ optionsJSON: goodOpts1, useBrowserAutofill: true }),
      Error,
      'does not support WebAuthn autofill',
    );
  });

  it('should throw error if no acceptable <input> is found', async () => {
    // <input> is missing "webauthn" from the autocomplete attribute
    const dom = new JSDOM(`
      <form>
        <label for="username">Username</label>
        <input type="text" name="username" autocomplete="username" />
        <button type="submit">Submit</button>
      </form>
    `);
    globalThis.document = dom.window.document;

    await assertRejects(
      () => startAuthentication({ optionsJSON: goodOpts1, useBrowserAutofill: true }),
      Error,
      'No <input>',
    );

    // @ts-ignore: Cleanup
    delete globalThis.document;
  });

  it('should not throw error when autofill input verification flag is false', async () => {
    // No suitable <input> is present in the "light DOM", which would normally raise...
    const dom = new JSDOM('<swan-autofill></swan-autofill>');
    globalThis.document = dom.window.document;

    // ...But a suitable <input> IS inside of a web component's "shadow DOM" and we know it
    const swanAutofill = globalThis.document.querySelector('swan-autofill');
    const shadowRoot = swanAutofill!.attachShadow({ mode: 'open' });
    shadowRoot.innerHTML = `
      <label for="username">Username</label>
      <input
        type="text"
        name="username"
        autocomplete="username webauthn"
        autofocus
      />
    `;

    // We just want to ensure that `startAuthentication()` doesn't error out here
    const resp = await startAuthentication({
      optionsJSON: goodOpts1,
      useBrowserAutofill: true,
      verifyBrowserAutofillInput: false,
    });
    assert(resp);

    // @ts-ignore: Cleanup
    delete globalThis.document;
  });

  it('should throw error if "webauthn" is not final autocomplete token', async () => {
    /**
     * According to WHATWG "webauthn" must be the final token in the autocomplete attribute when
     * multiple tokens are present:
     * https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#autofill-detail-tokens
     */
    const dom = new JSDOM(`
      <form>
        <label for="username">Username</label>
        <input type="text" name="username" autocomplete="webauthn username" />
        <button type="submit">Submit</button>
      </form>
    `);
    globalThis.document = dom.window.document;

    await assertRejects(
      () => startAuthentication({ optionsJSON: goodOpts1, useBrowserAutofill: true }),
      Error,
      'No <input>',
    );

    // @ts-ignore: Cleanup
    delete globalThis.document;
  });

  it('should return authenticatorAttachment if present', async () => {
    // Mock extension return values from authenticator
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.get = async () => ({
      response: {},
      getClientExtensionResults: () => {},
      authenticatorAttachment: 'cross-platform',
    });

    const response = await startAuthentication({ optionsJSON: goodOpts1 });

    assertEquals(response.authenticatorAttachment, 'cross-platform');
  });
});

describe('WebAuthnError', () => {
  // describe('AbortError', () => {
  //   const AbortError = generateCustomError('AbortError');

  //   /**
  //    * We can't actually test this because nothing in startAuthentication() propagates the abort
  //    * signal. But if you invoked WebAuthn via this and then manually sent an abort signal I guess
  //    * this will catch.
  //    *
  //    * As a matter of fact I couldn't actually get any browser to respect the abort signal...
  //    */
  //   it.skip('should identify abort signal', async () => {
  //     mockNavigatorGet.mockRejectedValueOnce(AbortError);

  //     const rejected = await expect(startAuthentication({ optionsJSON: goodOpts1 })).rejects;
  //     rejected.toThrow(WebAuthnError);
  //     rejected.toThrow(/abort signal/i);
  //     rejected.toHaveProperty('name', 'AbortError');
  //     rejected.toHaveProperty('code', 'ERROR_CEREMONY_ABORTED');
  //     rejected.toHaveProperty('cause', AbortError);
  //   });
  // });

  describe('NotAllowedError', () => {
    it('should pass through error message (iOS Safari - Operation failed)', async () => {
      /**
       * Thrown when biometric is not enrolled, or a Safari bug prevents conditional UI from being
       * aborted properly between page reloads.
       *
       * See https://github.com/MasterKale/SimpleWebAuthn/discussions/350#discussioncomment-4896572
       */
      const NotAllowedError = generateCustomError(
        'NotAllowedError',
        'Operation failed.',
      );

      const getSpy = spy(async () => {
        throw NotAllowedError;
      });

      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { get: getSpy };

      const rejected = await assertRejects(
        () => startAuthentication({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        'Operation failed',
      );

      assertEquals(rejected.name, 'NotAllowedError');
      assertEquals(rejected.code, 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY');
      assertEquals(rejected.cause, NotAllowedError);
    });

    it('should pass through error message (Chrome M110 - Bad TLS Cert)', async () => {
      /**
       * Starting from Chrome M110, WebAuthn is blocked if the site is being displayed on a URL with
       * TLS certificate issues. This includes during development.
       *
       * See https://github.com/MasterKale/SimpleWebAuthn/discussions/351#discussioncomment-4910458
       */
      const NotAllowedError = generateCustomError(
        'NotAllowedError',
        'WebAuthn is not supported on sites with TLS certificate errors.',
      );

      const getSpy = spy(async () => {
        throw NotAllowedError;
      });

      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { get: getSpy };

      const rejected = await assertRejects(
        () => startAuthentication({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        'sites with TLS certificate errors',
      );

      assertEquals(rejected.name, 'NotAllowedError');
      assertEquals(rejected.code, 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY');
      assertEquals(rejected.cause, NotAllowedError);
    });
  });

  describe('SecurityError', () => {
    const SecurityError = generateCustomError('SecurityError');

    beforeEach(() => {
      const getSpy = spy(async () => {
        throw SecurityError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { get: getSpy };

      // @ts-ignore
      globalThis.location = { hostname: '' } as unknown;
      // @ts-ignore
      globalThis.window = globalThis;
    });

    it('should identify invalid domain', async () => {
      globalThis.location.hostname = '1.2.3.4';

      const rejected = await assertRejects(
        () => startAuthentication({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        '1.2.3.4 is an invalid domain',
      );

      assertEquals(rejected.name, 'SecurityError');
      assertEquals(rejected.code, 'ERROR_INVALID_DOMAIN');
      assertEquals(rejected.cause, SecurityError);
    });

    it('should identify invalid RP ID', async () => {
      globalThis.location.hostname = 'simplewebauthn.com';

      const rejected = await assertRejects(
        () => startAuthentication({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        `RP ID "${goodOpts1.rpId}" is invalid for this domain`,
      );

      assertEquals(rejected.name, 'SecurityError');
      assertEquals(rejected.code, 'ERROR_INVALID_RP_ID');
      assertEquals(rejected.cause, SecurityError);
    });
  });

  describe('UnknownError', () => {
    const UnknownError = generateCustomError('UnknownError');

    beforeEach(() => {
      const getSpy = spy(async () => {
        throw UnknownError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { get: getSpy };

      // @ts-ignore
      globalThis.location = { hostname: '' } as unknown;
      // @ts-ignore
      globalThis.window = globalThis;
    });

    it('should identify potential authenticator issues', async () => {
      const rejected = await assertRejects(
        () => startAuthentication({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        'authenticator',
      );

      assertStringIncludes(rejected.message, 'unable to process the specified options');
      assertStringIncludes(rejected.message, 'could not create a new assertion signature');

      assertEquals(rejected.name, 'UnknownError');
      assertEquals(rejected.code, 'ERROR_AUTHENTICATOR_GENERAL_ERROR');
      assertEquals(rejected.cause, UnknownError);
    });
  });
});
