/* eslint-disable @typescript-eslint/ban-ts-comment */
/**
 * A custom Error used to return a more nuanced error detailing _why_ one of the eight documented
 * errors in the spec was raised after calling `navigator.credentials.create()` or
 * `navigator.credentials.get()`:
 *
 * - `AbortError`
 * - `ConstraintError`
 * - `InvalidStateError`
 * - `NotAllowedError`
 * - `NotSupportedError`
 * - `SecurityError`
 * - `TypeError`
 * - `UnknownError`
 *
 * Error messages were determined through investigation of the spec to determine under which
 * scenarios a given error would be raised.
 */
export class WebAuthnError extends Error {
  code: SimpleWebAuthnErrorCode;

  constructor({
    message,
    code,
    cause,
    name,
  }: {
    message: string,
    code: SimpleWebAuthnErrorCode,
    cause: Error,
    name?: string,
  }) {
    /**
     * `cause` is supported in evergreen browsers, but not IE10, so this ts-ignore is to
     * help Rollup complete the ES5 build.
     */
    // @ts-ignore
    super(message, { cause })
    this.name = name ?? cause.name;
    this.code = code;
  }
}

export type SimpleWebAuthnErrorCode =
  'ERROR_CEREMONY_ABORTED'
  | 'ERROR_INVALID_DOMAIN'
  | 'ERROR_INVALID_RP_ID'
  | 'ERROR_INVALID_USER_ID_LENGTH'
  | 'ERROR_AUTHENTICATOR_GENERAL_ERROR'
  | 'ERROR_AUTHENTICATOR_MISSING_DISCOVERABLE_CREDENTIAL_SUPPORT'
  | 'ERROR_AUTHENTICATOR_MISSING_USER_VERIFICATION_SUPPORT'
  | 'ERROR_AUTHENTICATOR_PREVIOUSLY_REGISTERED'
  | 'ERROR_AUTHENTICATOR_NO_SUPPORTED_PUBKEYCREDPARAMS_ALG'
  | 'ERROR_MALFORMED_PUBKEYCREDPARAMS'
  | 'ERROR_PASSTHROUGH_SEE_CAUSE_PROPERTY'
  ;
