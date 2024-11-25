/// <reference lib="DOM" />
import { assertEquals, assertInstanceOf, assertRejects, assertStringIncludes } from '@std/assert';
import { assertSpyCalls, type Spy, spy, stub } from '@std/testing/mock';
import { afterEach, beforeEach, describe, it } from '@std/testing/bdd';
import {
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  PublicKeyCredentialCreationOptionsJSON,
} from '@simplewebauthn/types';

import { generateCustomError } from '../helpers/__jest__/generateCustomError.ts';
import { _browserSupportsWebAuthnInternals } from '../helpers/browserSupportsWebAuthn.ts';
import { base64URLStringToBuffer } from '../helpers/base64URLStringToBuffer.ts';
import { WebAuthnError } from '../helpers/webAuthnError.ts';
import { WebAuthnAbortService } from '../helpers/webAuthnAbortService.ts';

import { startRegistration } from './startRegistration.ts';

const goodOpts1: PublicKeyCredentialCreationOptionsJSON = {
  challenge: '1T6uHri4OAQ',
  attestation: 'direct',
  pubKeyCredParams: [
    {
      alg: -7,
      type: 'public-key',
    },
  ],
  rp: {
    id: 'simplewebauthn.dev',
    name: 'SimpleWebAuthn',
  },
  user: {
    id: 'f4pdy3fpA34',
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

/**
 * A basic method we can resolve when mocking `navigator.credentials.create()` so _something_ gets
 * returned
 */
const defaultCreateResponse = async (...args: any[]) => ({
  response: {},
  getClientExtensionResults: () => ({}),
});

describe('Method: startRegistration', () => {
  let createSpy: Spy;

  beforeEach(() => {
    // Stub out a response so the method won't throw
    createSpy = spy(defaultCreateResponse);
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials = { create: createSpy };

    // Assume WebAuthn is available
    _browserSupportsWebAuthnInternals.stubThis = () => true;
  });

  afterEach(() => {
    // Reset the abort service so we get an accurate call count
    WebAuthnAbortService.cancelCeremony();
  });

  it('should convert options before passing to navigator.credentials.create(...)', async () => {
    await startRegistration({ optionsJSON: goodOpts1 });

    const args = createSpy.calls.at(0)?.args[0] as CredentialCreationOptions;
    const argsPublicKey = args.publicKey!;
    const credId = argsPublicKey.excludeCredentials?.[0].id;

    // Make sure challenge and user.id are converted to Buffers
    assertEquals(
      new Uint8Array(argsPublicKey.challenge as ArrayBuffer),
      new Uint8Array([213, 62, 174, 30, 184, 184, 56, 4]),
    );
    assertEquals(
      new Uint8Array(argsPublicKey.user.id as ArrayBuffer),
      new Uint8Array([127, 138, 93, 203, 119, 233, 3, 126]),
    );

    // Confirm construction of excludeCredentials array
    assertInstanceOf(credId, ArrayBuffer);
    assertEquals(credId.byteLength, 64);
    assertEquals(argsPublicKey.excludeCredentials?.[0].type, 'public-key');
    assertEquals(argsPublicKey.excludeCredentials?.[0].transports, ['internal']);
  });

  it('should return base64url-encoded response values', async () => {
    globalThis.navigator.credentials.create = async () => ({
      id: '6mUg8GzxDxs',
      rawId: base64URLStringToBuffer('6mUg8GzxDxs'),
      response: {
        attestationObject: new Uint8Array([1, 2, 3, 4]),
        clientDataJSON: new Uint8Array([5, 6, 7, 8]),
        getTransports: () => [],
        getAuthenticatorData: () => new Uint8Array(),
        getPublicKey: () => null,
        getPublicKeyAlgorithm: () => -999,
      },
      getClientExtensionResults: () => ({}),
      type: 'public-key',
      authenticatorAttachment: '',
    });

    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.rawId, '6mUg8GzxDxs');
    assertEquals(response.response.attestationObject, 'AQIDBA');
    assertEquals(response.response.clientDataJSON, 'BQYHCA');
  });

  it("should throw error if WebAuthn isn't supported", async () => {
    _browserSupportsWebAuthnInternals.stubThis = () => false;

    await assertRejects(
      () => startRegistration({ optionsJSON: goodOpts1 }),
      Error,
      'WebAuthn is not supported in this browser',
    );
  });

  it('should throw error if attestation is cancelled for some reason', async () => {
    globalThis.navigator.credentials.create = async () => null;

    await assertRejects(
      () => startRegistration({ optionsJSON: goodOpts1 }),
      Error,
      'Registration was not completed',
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

    const optsWithExts: PublicKeyCredentialCreationOptionsJSON = {
      ...goodOpts1,
      extensions,
    };

    await startRegistration({ optionsJSON: optsWithExts });

    const args = createSpy.calls.at(0)?.args[0] as CredentialCreationOptions;
    const argsPublicKey = args.publicKey!;
    const argsExtensions = argsPublicKey.extensions;

    assertEquals(argsExtensions, extensions);
  });

  it('should not set any extensions if not present in options', async () => {
    await startRegistration({ optionsJSON: goodOpts1 });

    const args = createSpy.calls.at(0)?.args[0] as CredentialCreationOptions;
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

    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.create = async () => ({
      response: {},
      getClientExtensionResults: () => extResults,
    });

    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.clientExtensionResults, extResults);
  });

  it('should include extension results when no extensions specified', async () => {
    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.clientExtensionResults, {});
  });

  it('should support "cable" transport in excludeCredentials', async () => {
    const opts: PublicKeyCredentialCreationOptionsJSON = {
      ...goodOpts1,
      excludeCredentials: [
        {
          ...goodOpts1.excludeCredentials![0],
          transports: ['cable'],
        },
      ],
    };

    await startRegistration({ optionsJSON: opts });

    const args = createSpy.calls.at(0)?.args[0] as CredentialCreationOptions;
    const argsPublicKey = args.publicKey!;

    assertEquals(
      argsPublicKey?.excludeCredentials?.[0].transports?.[0],
      'cable',
    );
  });

  it('should return "cable" transport from response', async () => {
    globalThis.navigator.credentials.create = async () => ({
      id: '6mUg8GzxDxs',
      rawId: base64URLStringToBuffer('6mUg8GzxDxs'),
      response: {
        attestationObject: new Uint8Array([1, 2, 3, 4]),
        clientDataJSON: new Uint8Array([1, 2, 3, 4]),
        getTransports: () => ['cable'],
      },
      getClientExtensionResults: () => ({}),
      type: 'webauthn.create',
    });

    const regResponse = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(regResponse.response.transports, ['cable']);
  });

  it('should cancel an existing call when executed again', async () => {
    const abortSpy = spy(AbortController.prototype, 'abort');

    // Fire off a request and immediately attempt a second one
    startRegistration({ optionsJSON: goodOpts1 });
    await startRegistration({ optionsJSON: goodOpts1 });
    assertSpyCalls(abortSpy, 1);
  });

  it('should return authenticatorAttachment if present', async () => {
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.create = async () => ({
      response: {},
      getClientExtensionResults: () => {},
      authenticatorAttachment: 'cross-platform',
    });

    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.authenticatorAttachment, 'cross-platform');
  });

  it('should return convenience values if getters present', async () => {
    /**
     * I call them "convenience values" because the getters for public key algorithm,
     * public key bytes, and authenticator data are alternative ways to access information
     * that's already buried in the response.
     */
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.create = async () => ({
      response: {
        getPublicKeyAlgorithm: () => 777,
        getPublicKey: () => new Uint8Array([0, 0, 0, 0]).buffer,
        getAuthenticatorData: () => new Uint8Array([0, 0, 0, 0]).buffer,
      },
      getClientExtensionResults: () => {},
    });

    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.response.publicKeyAlgorithm, 777);
    assertEquals(response.response.publicKey, 'AAAAAA');
    assertEquals(response.response.authenticatorData, 'AAAAAA');
  });

  it('should not return convenience values if getters missing', async () => {
    /**
     * I call them "convenience values" because the getters for public key algorithm,
     * public key bytes, and authenticator data are alternative ways to access information
     * that's already buried in the response.
     */
    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.create = async () => ({
      response: {},
      getClientExtensionResults: () => {},
    });

    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.response.publicKeyAlgorithm, undefined);
    assertEquals(response.response.publicKey, undefined);
    assertEquals(response.response.authenticatorData, undefined);
  });

  it('should survive browser extensions that intercept WebAuthn and incorrectly implement public key value getters', async () => {
    /**
     * 1Password browser extension v2.15.1 (the one that introduced passkeys support) seemed to have
     * implemented the following methods on AuthenticatorAttestationResponse...
     *
     * - getPublicKeyAlgorithm()
     * - getPublicKey()
     * - getAuthenticatorData()
     *
     * ...But when you attempt to call them as methods they'll error out with `TypeError`'s:
     *
     * Safari:
     * > TypeError: Can only call AuthenticatorAttestationResponse.getPublicKeyAlgorithm on instances
     * > of AuthenticatorAttestationResponse
     *
     * Chrome:
     * > TypeError: Illegal invocation
     *
     * Firefox:
     * > N/A (it handled it fine for some reason)
     *
     * Make sure `startRegistration()` can survive this scenario.
     *
     * See https://github.com/MasterKale/SimpleWebAuthn/issues/438 for more context.
     */

    // @ts-ignore: Super lame, making me stub out credman like this
    globalThis.navigator.credentials.create = async () => ({
      // Mock extension return values from the browser extension intercepting WebAuthn
      response: {
        getPublicKeyAlgorithm: () => {
          throw new Error('I throw for some reason');
        },
        getPublicKey: () => {
          throw new Error('I also throw for some reason');
        },
        getAuthenticatorData: () => {
          throw new Error('I throw for some reason too');
        },
      },
      getClientExtensionResults: () => {},
    });

    // Quiet down the `console.warn()` output when the getters above throw
    const stubConsoleWarn = stub(console, 'warn');

    const response = await startRegistration({ optionsJSON: goodOpts1 });

    assertEquals(response.response.publicKeyAlgorithm, undefined);
    assertEquals(response.response.publicKey, undefined);
    assertEquals(response.response.authenticatorData, undefined);

    stubConsoleWarn.restore();
  });

  it('should automatically register a.k.a. Conditional Create', async () => {
    await startRegistration({ optionsJSON: goodOpts1, useAutoRegister: true });

    const args = createSpy.calls.at(0)?.args[0] as CredentialCreationOptions;
    const argsMediation = (args as any).mediation;

    // The most important bit
    assertEquals(argsMediation, 'conditional');
  });
});

describe('WebAuthnError', () => {
  beforeEach(() => {
    _browserSupportsWebAuthnInternals.stubThis = () => true;
  });

  // describe('AbortError', () => {
  //   const AbortError = generateCustomError('AbortError');
  //   /**
  //    * We can't actually test this because nothing in startRegistration() propagates the abort
  //    * signal. But if you invoked WebAuthn via this and then manually sent an abort signal I guess
  //    * this will catch.
  //    *
  //    * As a matter of fact I couldn't actually get any browser to respect the abort signal...
  //    */
  //   Deno.test('should identify abort signal', async () => {
  //     mockNavigatorCreate.mockRejectedValueOnce(AbortError);

  //     const rejected = await expect(startRegistration({ optionsJSON: goodOpts1 })).rejects;
  //     rejected.toThrow(WebAuthnError);
  //     rejected.toThrow(/abort signal/i);
  //     rejected.toThrow(/AbortError/);
  //     rejected.toHaveProperty('code', 'ERROR_CEREMONY_ABORTED');
  //     rejected.toHaveProperty('cause', AbortError);
  //   });
  // });

  describe('ConstraintError', () => {
    const ConstraintError = generateCustomError('ConstraintError');

    beforeEach(() => {
      const createSpy = spy(async () => {
        throw ConstraintError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };
    });

    it('should identify unsupported discoverable credentials', async () => {
      const opts: PublicKeyCredentialCreationOptionsJSON = {
        ...goodOpts1,
        authenticatorSelection: {
          residentKey: 'required',
          requireResidentKey: true,
        },
      };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: opts }),
        WebAuthnError,
        'Discoverable credentials were required',
      );

      assertStringIncludes(rejected.message.toLowerCase(), 'no available authenticator supported');
      assertEquals(rejected.name, 'ConstraintError');
      assertEquals(rejected.code, 'ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT');
      assertEquals(rejected.cause, ConstraintError);
    });

    it('should identify unsupported user verification', async () => {
      const opts: PublicKeyCredentialCreationOptionsJSON = {
        ...goodOpts1,
        authenticatorSelection: {
          userVerification: 'required',
        },
      };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: opts }),
        WebAuthnError,
        'User verification was required',
      );

      assertStringIncludes(rejected.message.toLowerCase(), 'no available authenticator supported');
      assertEquals(rejected.name, 'ConstraintError');
      assertEquals(rejected.code, 'ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT');
      assertEquals(rejected.cause, ConstraintError);
    });

    it('should identify unsupported user verification during auto registration', async () => {
      const opts: PublicKeyCredentialCreationOptionsJSON = {
        ...goodOpts1,
        authenticatorSelection: {
          userVerification: 'required',
        },
      };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: opts, useAutoRegister: true }),
        WebAuthnError,
        'User verification was required during automatic registration',
      );

      assertStringIncludes(rejected.message.toLowerCase(), 'could not be performed');
      assertEquals(rejected.name, 'ConstraintError');
      assertEquals(rejected.code, 'ERROR_AUTO_REGISTER_USER_VERIFICATION_FAILURE');
      assertEquals(rejected.cause, ConstraintError);
    });
  });

  describe('InvalidStateError', () => {
    const InvalidStateError = generateCustomError('InvalidStateError');

    beforeEach(() => {
      const createSpy = spy(async () => {
        throw InvalidStateError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };
    });

    it('should identify re-registration attempt', async () => {
      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        'authenticator was previously registered',
      );

      assertEquals(rejected.name, 'InvalidStateError');
      assertEquals(rejected.code, 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED');
      assertEquals(rejected.cause, InvalidStateError);
    });
  });

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

      const createSpy = spy(async () => {
        throw NotAllowedError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: goodOpts1 }),
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

      const createSpy = spy(async () => {
        throw NotAllowedError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        'sites with TLS certificate errors',
      );

      assertEquals(rejected.name, 'NotAllowedError');
      assertEquals(rejected.code, 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY');
      assertEquals(rejected.cause, NotAllowedError);
    });
  });

  describe('NotSupportedError', () => {
    const NotSupportedError = generateCustomError('NotSupportedError');

    beforeEach(() => {
      const createSpy = spy(async () => {
        throw NotSupportedError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };
    });

    it('should identify missing "public-key" entries in pubKeyCredParams', async () => {
      const opts = {
        ...goodOpts1,
        pubKeyCredParams: [],
      };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: opts }),
        WebAuthnError,
        'pubKeyCredParams',
      );

      assertStringIncludes(rejected.message, 'public-key');
      assertEquals(rejected.name, 'NotSupportedError');
      assertEquals(rejected.code, 'ERROR_MALFORMED_PUBKEYCREDPARAMS');
      assertEquals(rejected.cause, NotSupportedError);
    });

    it('should identify no authenticator supports algs in pubKeyCredParams', async () => {
      const opts: PublicKeyCredentialCreationOptionsJSON = {
        ...goodOpts1,
        pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: opts }),
        WebAuthnError,
        'No available authenticator',
      );

      assertStringIncludes(rejected.message, 'pubKeyCredParams');
      assertEquals(rejected.name, 'NotSupportedError');
      assertEquals(rejected.code, 'ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG');
      assertEquals(rejected.cause, NotSupportedError);
    });
  });

  describe('SecurityError', () => {
    const SecurityError = generateCustomError('SecurityError');

    beforeEach(() => {
      const createSpy = spy(async () => {
        throw SecurityError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };

      // @ts-ignore
      globalThis.location = { hostname: '' } as unknown;
      // @ts-ignore
      globalThis.window = globalThis;
    });

    it('should identify invalid domain', async () => {
      globalThis.location.hostname = '1.2.3.4';

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: goodOpts1 }),
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
        () => startRegistration({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        `RP ID "${goodOpts1.rp.id}" is invalid for this domain`,
      );

      assertEquals(rejected.name, 'SecurityError');
      assertEquals(rejected.code, 'ERROR_INVALID_RP_ID');
      assertEquals(rejected.cause, SecurityError);
    });
  });

  describe('TypeError', () => {
    it('should identify malformed user ID', async () => {
      const typeError = new TypeError('user id is bad');

      const createSpy = spy(async () => {
        throw typeError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };

      const opts = {
        ...goodOpts1,
        user: {
          ...goodOpts1.user,
          // A base64url string 100 characters long should decode to ~70 bytes
          id: Array(100).fill('a').join(''),
        },
      };

      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: opts }),
        WebAuthnError,
        'User ID was not between 1 and 64 characters',
      );

      assertEquals(rejected.name, 'TypeError');
      assertEquals(rejected.code, 'ERROR_INVALID_USER_ID_LENGTH');
      assertEquals(rejected.cause, typeError);
    });
  });

  describe('UnknownError', () => {
    const UnknownError = generateCustomError('UnknownError');

    beforeEach(() => {
      const createSpy = spy(async () => {
        throw UnknownError;
      });
      // @ts-ignore: Super lame, making me stub out credman like this
      globalThis.navigator.credentials = { create: createSpy };
    });

    it('should identify potential authenticator issues', async () => {
      const rejected = await assertRejects(
        () => startRegistration({ optionsJSON: goodOpts1 }),
        WebAuthnError,
        'authenticator',
      );

      assertStringIncludes(rejected.message, 'unable to process the specified options');
      assertStringIncludes(rejected.message, 'could not create a new credential');
      assertEquals(rejected.name, 'UnknownError');
      assertEquals(rejected.code, 'ERROR_AUTHENTICATOR_GENERAL_ERROR');
      assertEquals(rejected.cause, UnknownError);
    });
  });
});
