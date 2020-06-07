# Changelog

## v0.6.0 - The one with better response verification

- **[server]** (BREAKING) Server's `verifyAttestationResponse()` and `verifyAssertionResponse()` methods now take a single arguments object.
- **[server]** These methods now include the ability to require user verification during attestation and assertion verification via the new `requireUserVerification` argument.

## v0.5.1

- **[typescript-types]** Re-export `AuthenticatorAttestationResponseJSON` and `AuthenticatorAssertionResponseJSON`

## v0.5.0 - The one where browser returns more info

- **[browser]** (BREAKING) Refactor `startAttestation()` and `startAssertion()` to return more of the output from the `navigator.credentials` calls
- **[browser]** Replace `base64-js` dependency with internal functionality
- **[browser, server]** Standardize on use of Base64URL encoding when converting to and from JSON
- **[server]** (BREAKING) Remove references to "base64" from `generateAttestationOptions()` and `generateAssertionOptions()` by renaming the `excludedBase64CredentialIDs` and `allowedBase64CredentialIDs` to `excludedCredentialIDs` and `allowedCredentialIDs` respectively
- **[typescript-types]** (BREAKING) Migrate some non-shared typings into **server**
