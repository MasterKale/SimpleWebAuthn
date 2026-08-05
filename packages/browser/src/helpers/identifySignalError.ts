import { isValidDomain } from './isValidDomain.ts';
import { WebAuthnError } from './webAuthnError.ts';
import type {
  SendSignalAllAcceptedCredentialsOpts,
  SendSignalCurrentUserDetailsOpts,
  SendSignalUnknownCredentialOpts,
} from '../methods/sendSignal.ts';

/**
 * Attempt to intuit _why_ an error was raised after calling one of the WebAuthn Signal APIs
 */
export function identifySignalError({ error, options }: {
  error: Error;
  options:
    | SendSignalUnknownCredentialOpts
    | SendSignalAllAcceptedCredentialsOpts
    | SendSignalCurrentUserDetailsOpts;
}): WebAuthnError {
  /**
   * General Signal API error conditions
   */
  if (error.name === 'SecurityError') {
    const effectiveDomain = globalThis.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      // https://w3c.github.io/webauthn/#sctn-signal-methods-async-rp-id-validation (Step 1)
      return new WebAuthnError({
        message: `"${globalThis.location.hostname}" is an invalid domain`,
        code: 'ERROR_INVALID_DOMAIN',
        cause: error,
      });
    }

    // https://w3c.github.io/webauthn/#sctn-signal-methods-async-rp-id-validation (Step 3)
    return new WebAuthnError({
      message:
        `The browser does not support Related Origins to enable signals for RP ID "${options.rpID}" on domain "${globalThis.location.hostname}"`,
      code: 'ERROR_INVALID_RP_ID',
      cause: error,
    });
  }

  /**
   * Signal-specific error conditions
   */
  if (options.signalName === 'unknownCredential') {
    if (error.name === 'TypeError') {
      // https://w3c.github.io/webauthn/#sctn-signalUnknownCredential (Step 1)
      return new WebAuthnError({
        message: 'credentialID is an invalid base64url string',
        code: 'ERROR_SIGNAL_INVALID_ARGUMENT',
        cause: error,
      });
    }
  } else if (options.signalName === 'allAcceptedCredentials') {
    if (error.name === 'TypeError') {
      // https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials (Step 1)
      // https://w3c.github.io/webauthn/#sctn-signalAllAcceptedCredentials (Step 2)
      return new WebAuthnError({
        message: 'userID, or an entry in allAcceptedCredentialIDs, is an invalid base64url string',
        code: 'ERROR_SIGNAL_INVALID_ARGUMENT',
        cause: error,
      });
    }
  } else if (options.signalName === 'currentUserDetails') {
    if (error.name === 'TypeError') {
      // https://w3c.github.io/webauthn/#sctn-signalCurrentUserDetails
      return new WebAuthnError({
        message: 'userID is an invalid base64url string',
        code: 'ERROR_SIGNAL_INVALID_ARGUMENT',
        cause: error,
      });
    }
  }

  // Consistently return a WebAuthnError, but point to the original error for more info
  return new WebAuthnError({
    message: error.message,
    code: 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY',
    cause: error,
  });
}
