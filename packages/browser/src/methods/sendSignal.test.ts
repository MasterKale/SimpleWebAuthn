import { assertEquals, assertRejects } from '@std/assert';
import { assertSpyCall, assertSpyCalls, type Spy, spy } from '@std/testing/mock';
import { beforeEach, describe, it } from '@std/testing/bdd';

import { generateCustomError } from '../helpers/__jest__/generateCustomError.ts';
import type { Base64URLString } from '../types/index.ts';
import { WebAuthnError } from '../helpers/webAuthnError.ts';
import {
  sendSignal,
  type SendSignalAllAcceptedCredentialsOpts,
  type SendSignalCurrentUserDetailsOpts,
  type SendSignalUnknownCredentialOpts,
} from './sendSignal.ts';

const credentialID: Base64URLString = 'NYtMO7dYULX2NcXrpzp5ig';
const rpID = 'simplewebauthn.dev';
const userID = 'uHqO6EqtKu7UIG074emo5w';
const userName = 'SimpleWebAuthn';
const userDisplayName = 'SimpleWebAuthn (Browser)';

describe('Method: sendSignal()', () => {
  describe('Signal: unknownCredential', () => {
    let signalUnknownCredentialSpy: Spy;
    const signalName: SendSignalUnknownCredentialOpts['signalName'] = 'unknownCredential';

    beforeEach(() => {
      signalUnknownCredentialSpy = spy();

      // @ts-ignore: Set up PublicKeyCredential
      globalThis.PublicKeyCredential = () => {};
      // @ts-ignore: Set up signalUnknownCredential
      globalThis.PublicKeyCredential.signalUnknownCredential = signalUnknownCredentialSpy;
    });

    it('should call PublicKeyCredential.signalUnknownCredential', async () => {
      const returned = await sendSignal({ signalName, rpID, credentialID });

      assertSpyCalls(signalUnknownCredentialSpy, 1);
      assertSpyCall(signalUnknownCredentialSpy, 0, {
        args: [{ rpId: rpID, credentialId: credentialID }],
      });

      assertEquals(returned, undefined);
    });

    it('should reject when signal is unsupported', async () => {
      // @ts-ignore: Intentionally deleting this
      delete globalThis.PublicKeyCredential.signalUnknownCredential;

      await assertRejects(() => sendSignal({ signalName, rpID, credentialID }));
    });

    it('should identify incorrectly Base64URL-encoded credential ID', async () => {
      const TypeError = generateCustomError('TypeError');
      signalUnknownCredentialSpy = spy(async () => {
        throw TypeError;
      });

      // @ts-ignore: Set up PublicKeyCredential
      globalThis.PublicKeyCredential = () => {};
      // @ts-ignore: Set up signalUnknownCredential
      globalThis.PublicKeyCredential.signalUnknownCredential = signalUnknownCredentialSpy;

      const rejected = await assertRejects(
        () => sendSignal({ signalName, rpID, credentialID }),
        WebAuthnError,
        'invalid base64url string',
      );

      assertEquals(rejected.name, 'TypeError');
      assertEquals(rejected.code, 'ERROR_SIGNAL_INVALID_ARGUMENT');
      assertEquals(rejected.cause, TypeError);
    });
  });

  describe('Signal: allAcceptedCredentials', () => {
    let signalAllAcceptedCredentialsSpy: Spy;
    const signalName: SendSignalAllAcceptedCredentialsOpts['signalName'] = 'allAcceptedCredentials';

    beforeEach(() => {
      signalAllAcceptedCredentialsSpy = spy();

      // @ts-ignore: Set up PublicKeyCredential
      globalThis.PublicKeyCredential = () => {};
      // @ts-ignore: Set up signalAllAcceptedCredentials
      globalThis.PublicKeyCredential.signalAllAcceptedCredentials = signalAllAcceptedCredentialsSpy;
    });

    it('should call PublicKeyCredential.signalAllAcceptedCredentials', async () => {
      const returned = await sendSignal({
        signalName,
        rpID,
        userID,
        allAcceptedCredentialIDs: [credentialID],
      });

      assertSpyCalls(signalAllAcceptedCredentialsSpy, 1);
      assertSpyCall(signalAllAcceptedCredentialsSpy, 0, {
        args: [{ rpId: rpID, userId: userID, allAcceptedCredentialIds: [credentialID] }],
      });

      assertEquals(returned, undefined);
    });

    it('should reject when signal is unsupported', async () => {
      // @ts-ignore: Intentionally deleting this
      delete globalThis.PublicKeyCredential.signalAllAcceptedCredentials;

      await assertRejects(() =>
        sendSignal({ signalName, rpID, userID, allAcceptedCredentialIDs: [credentialID] })
      );
    });

    it('should identify incorrectly Base64URL-encoded userID or credential ID', async () => {
      const TypeError = generateCustomError('TypeError');
      signalAllAcceptedCredentialsSpy = spy(async () => {
        throw TypeError;
      });

      // @ts-ignore: Set up signalAllAcceptedCredentials
      globalThis.PublicKeyCredential.signalAllAcceptedCredentials = signalAllAcceptedCredentialsSpy;

      const rejected = await assertRejects(
        () => sendSignal({ signalName, rpID, userID, allAcceptedCredentialIDs: [credentialID] }),
        WebAuthnError,
        'invalid base64url string',
      );

      assertEquals(rejected.name, 'TypeError');
      assertEquals(rejected.code, 'ERROR_SIGNAL_INVALID_ARGUMENT');
      assertEquals(rejected.cause, TypeError);
    });
  });

  describe('Signal: currentUserDetails', () => {
    let signalCurrentUserDetailsSpy: Spy;
    const signalName: SendSignalCurrentUserDetailsOpts['signalName'] = 'currentUserDetails';

    beforeEach(() => {
      signalCurrentUserDetailsSpy = spy();

      // @ts-ignore: Set up PublicKeyCredential
      globalThis.PublicKeyCredential = () => {};
      // @ts-ignore: Set up signalCurrentUserDetails
      globalThis.PublicKeyCredential.signalCurrentUserDetails = signalCurrentUserDetailsSpy;
    });

    it('should call PublicKeyCredential.signalCurrentUserDetails', async () => {
      const returned = await sendSignal({ signalName, rpID, userID, userName, userDisplayName });

      assertSpyCalls(signalCurrentUserDetailsSpy, 1);
      assertSpyCall(signalCurrentUserDetailsSpy, 0, {
        args: [{ rpId: rpID, userId: userID, name: userName, displayName: userDisplayName }],
      });

      assertEquals(returned, undefined);
    });

    it('should reject when signal is unsupported', async () => {
      // @ts-ignore: Intentionally deleting this
      delete globalThis.PublicKeyCredential.signalCurrentUserDetails;

      await assertRejects(() =>
        sendSignal({ signalName, rpID, userID, userName, userDisplayName })
      );
    });

    it('should default to empty displayName when omitted', async () => {
      const returned = await sendSignal({ signalName, rpID, userID, userName });

      assertSpyCalls(signalCurrentUserDetailsSpy, 1);
      assertSpyCall(signalCurrentUserDetailsSpy, 0, {
        args: [{ rpId: rpID, userId: userID, name: userName, displayName: '' }],
      });

      assertEquals(returned, undefined);
    });

    it('should identify incorrectly Base64URL-encoded userID', async () => {
      const TypeError = generateCustomError('TypeError');
      signalCurrentUserDetailsSpy = spy(async () => {
        throw TypeError;
      });

      // @ts-ignore: Set up signalCurrentUserDetails
      globalThis.PublicKeyCredential.signalCurrentUserDetails = signalCurrentUserDetailsSpy;

      const rejected = await assertRejects(
        () => sendSignal({ signalName, rpID, userID, userName }),
        WebAuthnError,
        'invalid base64url string',
      );

      assertEquals(rejected.name, 'TypeError');
      assertEquals(rejected.code, 'ERROR_SIGNAL_INVALID_ARGUMENT');
      assertEquals(rejected.cause, TypeError);
    });
  });

  it('should identify invalid RP ID for domain when sending any signal', async () => {
    /**
     * I'm just testing one of the signals for now, this error is not specific to any of them
     */
    const SecurityError = generateCustomError('SecurityError');
    const signalUnknownCredentialSpy = spy(async () => {
      throw SecurityError;
    });

    // @ts-ignore: Setting up globalThis.location.hostname to be an invalid domain
    globalThis.location = { hostname: 'localhost2' } as unknown;
    // @ts-ignore: Set up PublicKeyCredential
    globalThis.PublicKeyCredential = () => {};
    // @ts-ignore: Set up signalUnknownCredential
    globalThis.PublicKeyCredential.signalUnknownCredential = signalUnknownCredentialSpy;

    const rejected = await assertRejects(
      () => sendSignal({ signalName: 'unknownCredential', rpID, credentialID }),
      WebAuthnError,
      'invalid domain',
    );

    assertEquals(rejected.name, 'SecurityError');
    assertEquals(rejected.code, 'ERROR_INVALID_DOMAIN');
    assertEquals(rejected.cause, SecurityError);
  });

  it('should identify missing Related Origins support when sending any signal', async () => {
    /**
     * I'm just testing one of the signals for now, this error is not specific to any of them
     */
    const SecurityError = generateCustomError('SecurityError');
    const signalUnknownCredentialSpy = spy(async () => {
      throw SecurityError;
    });

    // @ts-ignore: Setting up globalThis.location.hostname to be a valid domain
    globalThis.location = { hostname: 'localhost' } as unknown;
    // @ts-ignore: Set up PublicKeyCredential
    globalThis.PublicKeyCredential = () => {};
    // @ts-ignore: Set up signalUnknownCredential
    globalThis.PublicKeyCredential.signalUnknownCredential = signalUnknownCredentialSpy;

    const rejected = await assertRejects(
      () => sendSignal({ signalName: 'unknownCredential', rpID, credentialID }),
      WebAuthnError,
      'does not support Related Origins',
    );

    assertEquals(rejected.name, 'SecurityError');
    assertEquals(rejected.code, 'ERROR_INVALID_RP_ID');
    assertEquals(rejected.cause, SecurityError);
  });

  it('should default to passing through original error when sending any signal', async () => {
    /**
     * I'm just testing one of the signals for now, this error is not specific to any of them
     */
    // This error isn't one expected to be raised by a signal
    const ConstraintError = generateCustomError('ConstraintError');
    const signalUnknownCredentialSpy = spy(async () => {
      throw ConstraintError;
    });

    // @ts-ignore: Set up PublicKeyCredential
    globalThis.PublicKeyCredential = () => {};
    // @ts-ignore: Set up signalUnknownCredential
    globalThis.PublicKeyCredential.signalUnknownCredential = signalUnknownCredentialSpy;

    const rejected = await assertRejects(
      () => sendSignal({ signalName: 'unknownCredential', rpID, credentialID }),
      WebAuthnError,
    );

    assertEquals(rejected.name, 'ConstraintError');
    assertEquals(rejected.code, 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY');
    assertEquals(rejected.cause, ConstraintError);
  });
});
