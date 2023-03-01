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
  constructor(message: string, cause: Error, name?: string) {
    /**
     * `cause` is supported in evergreen browsers, but not IE10, so this ts-ignore is to
     * help Rollup complete the ES5 build.
     */
    // @ts-ignore
    super(message, { cause })
    // this.name = name ?? cause.name;
    this.name = name ?? cause.name;
  }
}
