# Changelog

## v0.8.2

**Packages:**

- @simplewebauthn/browser@0.8.2
- @simplewebauthn/server@0.8.2
- @simplewebauthn/typescript-types@0.8.2

**Changes:**

- **[server]** Return explicit defaults for `authenticatorSelection` in return value from `generateAttestationOptions()` for enhanced device compatibility.
- **[browser]** Version sync.
- **[typescript-types]** Version sync.

## v0.8.1

**Packages:**

- @simplewebauthn/server@0.8.1

**Changes:**

- **[server]** Stop filtering out algorithm ID's from `supportedAlgorithmIDs` when calling `generateAttestationOptions()`
- **[server]** Fix a bug when verifying TPM attestation extensions

## v0.8.0 - The one with better challenges

**Packages:**

- @simplewebauthn/browser@0.8.0
- @simplewebauthn/server@0.8.0
- @simplewebauthn/typescript-types@0.8.0

**Changes:**

- **[server]** The `challenge` parameter of `generateAttestationOptions()` and `generateAssertionOptions()` is now _optional_.
  - **When undefined** the library will generate a random challenge. This value will be base64url-encoded in preparation for transit to the front end.
  - **When defined** the value will be directly encoded to base64url in preparation for transit to the front end.
- **[browser]** `startAttestation()` and `startAssertion()` now convert the base64url-encoded `options.challenge` to a buffer before passing it to the authenticator.

### Breaking Changes

- **[server]** `verifyAttestationResponse()` and `verifyAssertionResponse()` now require the base64url-encoded challenge to be passed in as `expectedChallenge`:

Before:

```js
const challenge = 'someChallenge';

const opts = generateAttestationOptions({
  ...atteOpts,
  challenge,
});

const verification = verifyAttestationResponse({
  ...atteResp,
  // Raw original value
  expectedChallenge: challenge,
});
```

After:

```js
const challenge = 'someChallenge';

const opts = generateAttestationOptions({
  ...atteOpts,
  // This is now optional
  challenge,
});

const verification = verifyAttestationResponse({
  ...atteResp,
  // Now expected to be the base64url-encoded `challenge` returned
  // by `generateAttestationOptions()`
  expectedChallenge: opts.challenge,
});
```

## v0.7.4

**Packages:**

- @simplewebauthn/browser@0.7.4
- @simplewebauthn/server@0.7.4

**Changes:**

- **[browser]** Update dependencies
- **[server]** Update dependencies

## v0.7.3

**Packages:**

- @simplewebauthn/browser@0.7.3
- @simplewebauthn/server@0.7.3

**Changes:**

- **[browser]** Add support for UTF-8 values in server challenges
- **[server]** Minor performance improvement

## v0.7.2

**Packages:**

- @simplewebauthn/browser@0.7.2
- @simplewebauthn/server@0.7.2

**Changes:**

- **[server]** Added support for specifying a custom array of COSE algorithm identifiers when calling `generateAttestationOptions()` and `verifyAttestationResponse()`
- **[browser]** Updated README.md with new doc URLs

## v0.7.1

**Packages:**

- @simplewebauthn/browser@0.7.1
- @simplewebauthn/server@0.7.1
- @simplewebauthn/typescript-types@0.7.1

**Changes:**

- Fixed broken README and Homepage links in package listings on NPMJS.com

## v0.7.0 - The one that passes FIDO conformance testing

**Packages:**

- @simplewebauthn/browser@0.7.0
- @simplewebauthn/server@0.7.0
- @simplewebauthn/typescript-types@0.7.0

**Changes:**

- **[server]** Add support for TPM attestations
- **[server]** Add support for Android Key attestations
- **[server]** Add support for authenticator metadata statements and the FIDO Metadata Service (MDS)

### Breaking Changes

- **[server]** The return type of `verifyAttestationResponse()` changed from `boolean` to `Promise<boolean>`. This was necessary to support querying FIDO MDS for an authenticator metadata statement during attestation verification.
- **[server]** The optional `requireUserVerification` parameter of `verifyAssertionResponse()` has been replaced with the new optional `fidoUserVerification` parameter. This enables greater control over user verification when verifying assertions.

## v0.6.1

**Packages:**

- @simplewebauthn/server@0.6.1

**Changes:**

- **[typescript-types]** Update `verifyAttestationResponse()` options param description.

## v0.6.0 - The one with better response verification

**Packages:**

- @simplewebauthn/browser@0.6.0
- @simplewebauthn/server@0.6.0
- @simplewebauthn/typescript-types@0.6.0

**Changes:**

- **[server]** (BREAKING) Server's `verifyAttestationResponse()` and `verifyAssertionResponse()` methods now take a single arguments object.
- **[server]** These methods now include the ability to require user verification during attestation and assertion verification via the new `requireUserVerification` argument.

## v0.5.1

**Packages:**

- @simplewebauthn/typescript-types@0.5.1

**Changes:**

- **[typescript-types]** Re-export `AuthenticatorAttestationResponseJSON` and `AuthenticatorAssertionResponseJSON`

## v0.5.0 - The one where browser returns more info

**Packages:**

- @simplewebauthn/browser@0.5.0
- @simplewebauthn/server@0.5.0
- @simplewebauthn/typescript-types@0.5.0

**Changes:**

- **[browser]** (BREAKING) Refactor `startAttestation()` and `startAssertion()` to return more of the output from the `navigator.credentials` calls
- **[browser]** Replace `base64-js` dependency with internal functionality
- **[browser, server]** Standardize on use of Base64URL encoding when converting to and from JSON
- **[server]** (BREAKING) Remove references to "base64" from `generateAttestationOptions()` and `generateAssertionOptions()` by renaming the `excludedBase64CredentialIDs` and `allowedBase64CredentialIDs` to `excludedCredentialIDs` and `allowedCredentialIDs` respectively
- **[typescript-types]** (BREAKING) Migrate some non-shared typings into **server**
