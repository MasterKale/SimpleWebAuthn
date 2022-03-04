import { isValidDomain } from './isValidDomain';

export function identifyRegistrationError({ error, options }: {
  error: Error,
  options: CredentialCreationOptions,
}): WebAuthnError | Error {
  const { publicKey } = options;
  console.log(error);
  console.log(options);

  if (!publicKey) {
    throw Error('options was missing required publicKey property');
  }

  if (error.name === 'AbortError') {
    if (options.signal === (new AbortController()).signal) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 16)
      return new WebAuthnError('Registration ceremony was sent an abort signal');
    }
  } else if (error.name === 'ConstraintError') {
    if (publicKey.authenticatorSelection?.requireResidentKey === true) {
      // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 4)
      return new WebAuthnError(
        'Discoverable credentials were required but no available authenticator supported it',
      );
    } else if (publicKey.authenticatorSelection?.userVerification === 'required') {
      // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 5)
      return new WebAuthnError(
        'User verification was required but no available authenticator supported it',
      );
    }
  } else if (error.name === 'InvalidStateError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 20)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 3)
    return new WebAuthnError(
      'The user attempted to re-register an authenticator',
    );
  } else if (error.name === 'NotAllowedError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 20)
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 21)
    return new WebAuthnError('User clicked cancel, or the registration ceremony timed out');
  } else if (error.name === 'NotSupportedError') {
    const validPubKeyCredParams = publicKey.pubKeyCredParams.filter(
      (param) => param.type === 'public-key',
    );

    if (validPubKeyCredParams.length === 0) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 10)
      return new WebAuthnError('No entry in pubKeyCredParams was of type "public-key"');
    }

    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 2)
    return new WebAuthnError(
      'No available authenticator supported any of the specified pubKeyCredParams algorithms',
    );
  } else if (error.name === 'SecurityError') {
    const effectiveDomain = window.location.hostname;
    if (!isValidDomain(effectiveDomain)) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 7)
      return new WebAuthnError(`${window.location.hostname} is an invalid domain`);
    } else if (publicKey.rp.id !== effectiveDomain) {
      // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 8)
      return new WebAuthnError(`The RP ID "${publicKey.rp.id}" is invalid for this domain`);
    }
  } else if (error.name === 'TypeError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-createCredential (Step 5)
    return new WebAuthnError('User ID was not between 1 and 64 characters');
  } else if (error.name === 'UnknownError') {
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 1)
    // https://www.w3.org/TR/webauthn-2/#sctn-op-make-cred (Step 8)
    return new WebAuthnError(
      'The authenticator was unable to process the specified options, or could not create a new credential'
    );
  }

  return error;
}

class WebAuthnError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WebAuthnError';
  }
}
