# Changelog

## v13.2.2

**Changes**

- **[browser] [server]** In the spirit of contributing to
  [increased software supply chain transparency](https://docs.npmjs.com/trusted-publishers), both
  libraries are now published via GitHub Actions workflows. Package listings on
  [JSR](https://jsr.io/@simplewebauthn/server) and
  [NPM](https://www.npmjs.com/package/@simplewebauthn/server) feature build transparency logs at the
  bottom of their respective pages ([#725](https://github.com/MasterKale/SimpleWebAuthn/pull/725),
  [#726](https://github.com/MasterKale/SimpleWebAuthn/pull/726),
  [#727](https://github.com/MasterKale/SimpleWebAuthn/pull/727))

## v13.2.1

**Changes:**

- **[server]** `generateRegistrationOptions()` will now correctly encoded the `userID` argument to
  base64url when it is an instance of Node's `Buffer`
  ([#724](https://github.com/MasterKale/SimpleWebAuthn/pull/724))

## v13.2.0

**Changes**

- **[server]** The return value from `verifyRegistrationResponse()` has been defined more strictly
  to communicate that `registrationInfo` will only ever be present if `verified` is `true`
  ([#715](https://github.com/MasterKale/SimpleWebAuthn/pull/715))
- **[server]** `verifyRegistrationResponse()` can now verify attestations containing SHA256 hashes
  by using EC public keys with the P-384 curve
  ([#721](https://github.com/MasterKale/SimpleWebAuthn/pull/721))
- **[server]** The Android SafetyNet "CTS profile match" system integrity check can now be disabled
  by setting `attestationSafetyNetEnforceCTSCheck: false` when calling
  `verifyRegistrationResponse()`. This check remains enforced by default
  ([#722](https://github.com/MasterKale/SimpleWebAuthn/pull/722))
- **[browser] [server]** These libraries now have better support in Deno 2.2+ projects which use
  [generic typing for `Uint8Array` via TypeScript 5.7](https://typescriptdocs.com/release-notes/TypeScript%205.7.html#typedarrays-are-now-generic-over-arraybufferlike).
  SimpleWebAuthn values of type `Uint8Array_` are equivalent to `Uint8Array` in Deno 2.1 and
  earlier, and `Uint8Array<ArrayBuffer>` in Deno 2.2 and later.
  ([#717](https://github.com/MasterKale/SimpleWebAuthn/pull/717))

## v13.1.2

**Changes**

- **[browser] [server]** Exported the `ResidentKeyRequirement` type to help with type inference
  ([#704](https://github.com/MasterKale/SimpleWebAuthn/pull/704))

## v13.1.1

**Changes:**

- **[server]** `"android-key"` attestation statement verification has been modernized
  ([#675](https://github.com/MasterKale/SimpleWebAuthn/pull/675))
- **[server]** More TPM manufacturers are recognized while verifying `"tpm"` attestation statements
  ([#673](https://github.com/MasterKale/SimpleWebAuthn/pull/673))

## v13.1.0

**Changes:**

- **[server]** The `cross-fetch` dependency has been removed from the project to silence in the
  console `DeprecationWarning`'s about a "`punycode`" module
  ([#661](https://github.com/MasterKale/SimpleWebAuthn/pull/661))
- **[browser]** `startRegistration()` and `startAuthentication()` will now warn about calls made
  using the pre-v11 call structure to encourage refactoring to use the current call structure, but
  still try to handle such calls the best they can
  ([#664](https://github.com/MasterKale/SimpleWebAuthn/pull/664))

## v13.0.0 - The one where they share a type

Hot on the heels of the last major release, v13 introduces support for registration hints! Refined
types and improved attestation trust anchor verification are also included. Last but not least, we
say goodbye to one of the project's packages for better docs and fewer dependencies to install. Read
on for more information, including refactor advice for dealing with the retirement of
**@simplewebauthn/types**.

**Changes:**

- **[server]** A new `preferredAuthenticatorType` argument can be set when calling
  `generateRegistrationOptions()` to generate options that encourage the browser to direct the user
  to register one of three types of authenticators: `'securityKey'`, `'localDevice'`, or
  `'remoteDevice'` (a.k.a. opinionated
  [WebAuthn hints](https://w3c.github.io/webauthn/#dom-publickeycredentialcreationoptions-hints)
  support) ([#653](https://github.com/MasterKale/SimpleWebAuthn/pull/653))
- **[browser]** `startRegistration()` will recognize `hints` if specified in `optionsJSON`
  ([#652](https://github.com/MasterKale/SimpleWebAuthn/pull/652))
- **[server]** Attestation verification now recognizes intermediate certificates as trust anchors
  ([#650](https://github.com/MasterKale/SimpleWebAuthn/pull/650))
- **[browser] [server]** The types previously maintained in the **types** package are now included
  within the **browser** and **server** packages. See Breaking Changes below for more info
  ([#655](https://github.com/MasterKale/SimpleWebAuthn/pull/655))

### Breaking Changes

#### @typescript/types is being retired

Its types will now be included directly in **@simplewebauthn/browser** and
**@simplewebauthn/server**.

To refactor existing imports from **/types**, simply import them from **/browser** or **/server**
instead:

**Before:**

```ts
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from '@simplewebauthn/types'; // <--
```

**After:**

```ts
import type {
  AuthenticationResponseJSON,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from '@simplewebauthn/server'; // <--
```

---

#### [server] `attestationType` no longer accepts `'indirect'`

The benefits of indirect attestation are too minimal to be useful for Relying Parties. In practice
it is almost never used over ignoring the concept completely with `'none'` or needing to be
intentional and setting `'direct'`.

RP's that have been specifying `attestationType: 'indirect'` when calling
`generateRegistrationOptions()` will need to refactor their code to either **omit**
`attestationType` (`generateRegistrationOptions()` will default to `attestationType: 'none'`) or set
`attestationType: 'direct'` instead:

**Before:**

```ts
const options = await generateRegistrationOptions({
  // ...
  attestationType: 'indirect',
});
```

**After:**

```ts
const options = await generateRegistrationOptions({
  // ...
});
```

-or-

```ts
const options = await generateRegistrationOptions({
  // ...
  attestationType: 'direct',
});
```

## v12.0.0 - The one that claims a JSR scope

All SimpleWebAuthn packages are now available for installation from the
[JavaScript Registry (JSR)](https://jsr.io/@simplewebauthn)! JSR is an "open-source package registry
for modern JavaScript and TypeScript" - you can read more about this new package registry and its
ESM-centric capabilities [here](https://jsr.io/docs/why).

**All packages in v12.0.0 are functionally identical to v11.0.0!** And JSR package hosting is **in
addition to** existing package hosting on NPM. Nothing changes about package installation via
`npm install`. Read on for more information.

### Packages

- @simplewebauthn/browser@12.0.0
- @simplewebauthn/server@12.0.0
- @simplewebauthn/types@12.0.0

### Changes

- **[browser]** **[server]** **[types]** All packages can now be installed from JSR wherever JSR
  imports are supported ([#634](https://github.com/MasterKale/SimpleWebAuthn/pull/634))
- **[browser]** Deno projects using frameworks like Fresh can now import and use
  **@simplewebauthn/browser** ([#634](https://github.com/MasterKale/SimpleWebAuthn/pull/634))

To install from JSR, use `npx jsr add @simplewebauthn/...` or `deno add jsr:@simplewebauthn/...`
depending on which package manager is available.

#### Projects using `npm` for package management:

```sh
npx jsr add @simplewebauthn/browser
```

```sh
npx jsr add @simplewebauthn/server
```

```sh
npx jsr add @simplewebauthn/types
```

#### Projects using `deno` for package management:

```sh
deno add jsr:@simplewebauthn/browser
```

```sh
deno add jsr:@simplewebauthn/server
```

```sh
deno add jsr:@simplewebauthn/types
```

#### Projects using HTTPS modules via deno.land/x:

v12.0.0 officially deprecates importing SimpleWebAuthn from deno.land/x. See **Breaking Changes**
below for refactor guidance.

### Breaking Changes

Importing SimpleWebAuthn packages from `"https://deno.land/x/simplewebauthn/..."` URLs is no longer
supported. Please use Deno's native support for JSR imports instead, available in projects running
Deno v1.42 and higher.

**Before:**

```ts
import { generateAuthenticationOptions } from 'https://deno.land/x/simplewebauthn/deno/server.ts';
```

**After:**

```ts
import { generateAuthenticationOptions } from 'jsr:@simplewebauthn/server';
```

Alternatively, use `deno add` to install these packages from
**[JSR](https://jsr.io/@simplewebauthn)**:

```sh
# Deno v1.42 and higher
deno add jsr:@simplewebauthn/server
```

```ts
import { generateAuthenticationOptions } from '@simplewebauthn/server';
```

## v11.0.0 - The one that auto-registers

Say hello to support for automatic passkey registration, support for valid conditional UI `<input>`
elements stashed away in web components, and to the new `WebAuthnCredential` type that modernizes
some logic within.

There are some breaking changes in this release! Please see **Breaking Changes** below for refactor
guidance.

### Packages

- @simplewebauthn/browser@11.0.0
- @simplewebauthn/server@11.0.0
- @simplewebauthn/types@11.0.0

### Changes

- **[browser] [server]** A new `useAutoRegister` argument has been added to `startRegistration()` to
  support attempts to automatically register passkeys for users who just completed non-passkey auth.
  `verifyRegistrationResponse()` has gained a new `requireUserPresence` option that can be set to
  `false` when verifying responses from `startRegistration({ useAutoRegister: true, ... })`
  ([#623](https://github.com/MasterKale/SimpleWebAuthn/pull/623))
- **[browser]** A new `verifyBrowserAutofillInput` argument has been added to
  `startAuthentication()` to disable throwing an error when a correctly configured `<input>` element
  cannot be found (but perhaps a valid one is present in a web component shadow's DOM)
  ([#621](https://github.com/MasterKale/SimpleWebAuthn/pull/621))
- **[server] [types]** The `AuthenticatorDevice` type has been renamed to `WebAuthnCredential` and
  has had its properties renamed. The return value out of `verifyRegistrationResponse()` and
  corresponding inputs into `verifyAuthenticationResponse()` have been updated accordingly. See
  **Breaking Changes** below for refactor guidance
  ([#625](https://github.com/MasterKale/SimpleWebAuthn/pull/625))
- **[server]** `verifyRegistrationResponse()` now verifies that the authenticator data AAGUID
  matches the leaf cert's `id-fido-gen-ce-aaguid` extension AAGUID when it is present
  ([#609](https://github.com/MasterKale/SimpleWebAuthn/pull/609))
- **[server]** TPM attestation verification recognizes the corrected TPM manufacturer identifier for
  IBM ([#610](https://github.com/MasterKale/SimpleWebAuthn/pull/610))
- **[server]** Types for the defunct authenticator extensions `uvm` and `dpk` have been removed
  ([#611](https://github.com/MasterKale/SimpleWebAuthn/pull/611))

### Breaking Changes

#### [browser] Positional arguments in `startRegistration()` and `startAuthentication()` have been replaced by a single object

Property names in the object match the names of the previously-positional arguments. To update
existing implementations, wrap existing options in an object with corresponding properties:

**Before:**

```ts
startRegistration(options);
startAuthentication(options, true);
```

**After:**

```ts
startRegistration({ optionsJSON: options });
startAuthentication({ optionsJSON: options, useBrowserAutofill: true });
```

#### [server] [types] The `AuthenticatorDevice` type has been renamed to `WebAuthnCredential`

`AuthenticatorDevice.credentialID` and `AuthenticatorDevice.credentialPublicKey` have been shortened
to `WebAuthnCredential.id` and `WebAuthnCredential.publicKey` respectively.

`verifyRegistrationResponse()` has been updated accordingly to return a new `credential` value of
type `WebAuthnCredential`. Update code that stores `credentialID`, `credentialPublicKey`, and
`counter` out of `verifyRegistrationResponse()` to store `credential.id`, `credential.publicKey`,
and `credential.counter` instead:

**Before:**

```ts
const { registrationInfo } = await verifyRegistrationResponse({...});

storeInDatabase(
  registrationInfo.credentialID,
  registrationInfo.credentialPublicKey,
  registrationInfo.counter,
  body.response.transports,
);
```

**After:**

```ts
const { registrationInfo } = await verifyRegistrationResponse({...});

storeInDatabase(
  registrationInfo.credential.id,
  registrationInfo.credential.publicKey,
  registrationInfo.credential.counter,
  registrationInfo.credential.transports,
);
```

Update calls to `verifyAuthenticationResponse()` to match the new `credential` argument that
replaces the `authenticator` argument:

**Before:**

```ts
import { AuthenticatorDevice } from '@simplewebauthn/types';

const authenticator: AuthenticatorDevice = {
  credentialID: ...,
  credentialPublicKey: ...,
  counter: 0,
  transports: [...],
};

const verification = await verifyAuthenticationResponse({
  // ...
  authenticator,
});
```

**After:**

```ts
import { WebAuthnCredential } from '@simplewebauthn/types';

const credential: WebAuthnCredential = {
  id: ...,
  publicKey: ...,
  counter: 0,
  transports: [...],
};

const verification = await verifyAuthenticationResponse({
  // ...
  credential,
});
```

## v10.0.1

### Packages

- @simplewebauthn/server@10.0.1

### Changes

- **[server]** `isoCrypto.verify()` now has better support for signature verification with ECC
  public keys using P-256, P-385, and P-521 curves
  ([#594](https://github.com/MasterKale/SimpleWebAuthn/pull/594), with thanks to @nlordell)

## v10.0.0 - The one that goes up to 20

Thanks for everything, Node 16 and Node 18, but it's time to move on! The headlining change of this
release is the targeting of Node LTS v20+ as the minimum Node runtime. Additional developer-centric
quality-of-life changes have also been made in the name of streamlining use of SimpleWebAuthn on
both the back end and front end.

This release is packed with updates, so buckle up! Refactor advice for breaking changes is, as
always, offered below.

### Packages

- @simplewebauthn/browser@10.0.0
- @simplewebauthn/server@10.0.0
- @simplewebauthn/types@10.0.0

### Changes

- **[server]** The minimum supported Node version has been raised to Node v20
  ([#531](https://github.com/MasterKale/SimpleWebAuthn/pull/531))
- **[server]** `user.displayName` now defaults to an empty string if a value is not specified for
  `userDisplayName` when calling `generateRegistrationOptions()`
  ([#538](https://github.com/MasterKale/SimpleWebAuthn/pull/538))
- **[browser]** The `browserSupportsWebAuthnAutofill()` helper will no longer break in environments
  in which `PublicKeyCredential` is not present
  ([#557](https://github.com/MasterKale/SimpleWebAuthn/pull/557), with thanks to @clarafitzgerald)

### Breaking Changes

- **[server]** The following breaking changes were made in PR
  [#529](https://github.com/MasterKale/SimpleWebAuthn/pull/529):
  - `generateRegistrationOptions()` now expects `Base64URLString` for excluded credential IDs
  - `generateAuthenticationOptions()` now expects `Base64URLString` for allowed credential IDs
  - `credentialID` returned from response verification methods is now a `Base64URLString`
  - `AuthenticatorDevice.credentialID` is now a `Base64URLString`
  - `isoBase64URL.isBase64url()` is now called `isoBase64URL.isBase64URL()`
- **[browser, server]** The following breaking changes were made in PR
  [#552](https://github.com/MasterKale/SimpleWebAuthn/pull/552):
  - `generateRegistrationOptions()` now accepts an optional `Uint8Array` instead of a `string` for
    `userID`
  - `isoBase64URL.toString()` and `isoBase64URL.fromString()` have been renamed
  - `generateRegistrationOptions()` will now generate random user IDs
  - `user.id` is now treated like a base64url string in `startRegistration()`
  - `userHandle` is now treated like a base64url string in `startAuthentication()`
- **[server]** `rpID` is now a required argument when calling `generateAuthenticationOptions()`
  ([#555](https://github.com/MasterKale/SimpleWebAuthn/pull/555))

---

#### [server] `generateRegistrationOptions()` now expects `Base64URLString` for excluded credential IDs

The `isoBase64URL` helper can be used to massage `Uint8Array` credential IDs into base64url strings:

**Before**

```ts
const opts = await generateRegistrationOptions({
  // ...
  excludeCredentials: devices.map((dev) => ({
    id: dev.credentialID, // type: Uint8Array
    type: 'public-key',
    transports: dev.transports,
  })),
});
```

**After**

```ts
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const opts = await generateRegistrationOptions({
  // ...
  excludeCredentials: devices.map((dev) => ({
    id: isoBase64URL.fromBuffer(dev.credentialID), // type: string
    transports: dev.transports,
  })),
});
```

The `type` argument is no longer needed either.

---

#### [server] `generateAuthenticationOptions()` now expects `Base64URLString` for allowed credential IDs

Similarly, the `isoBase64URL` helper can also be used during auth to massage `Uint8Array` credential
IDs into base64url strings:

**Before**

```ts
const opts = await generateAuthenticationOptions({
  // ...
  allowCredentials: devices.map((dev) => ({
    id: dev.credentialID, // type: Uint8Array
    type: 'public-key',
    transports: dev.transports,
  })),
});
```

**After**

```ts
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const opts = await generateAuthenticationOptions({
  // ...
  allowCredentials: devices.map((dev) => ({
    id: isoBase64URL.fromBuffer(dev.credentialID), // type: Base64URLString (a.k.a string)
    transports: dev.transports,
  })),
});
```

The `type` argument is no longer needed either.

---

#### [server] `credentialID` returned from response verification methods is now a `Base64URLString`

It is no longer necessary to manually stringify `credentialID` out of response verification methods:

**Before**

```ts
import { isoBase64URL } from '@simplewebauthn/server/helpers';

// Registration
const { verified, registrationInfo } = await verifyRegistrationResponse({ ... });
if (verified && registrationInfo) {
  const { credentialID } = registrationInfo;
  await storeInDatabase({ credIDString: isoBase64URL.fromBuffer(credentialID), ... });
}

// Authentication
const { verified, authenticationInfo } = await verifyAuthenticationResponse({ ... });
if (verified && authenticationInfo) {
  const { newCounter, credentialID } = authenticationInfo;
  dbAuthenticator.counter = authenticationInfo.newCounter;
  await updateCounterInDatabase({
    credIDString: isoBase64URL.fromBuffer(credentialID),
    newCounter,
  });
}
```

**After**

```ts
// Registration
const { verified, registrationInfo } = await verifyRegistrationResponse({ ... });
if (verified && registrationInfo) {
  const { credentialID } = registrationInfo;
  await storeInDatabase({ credIDString: credentialID, ... });
}

// Authentication
const { verified, authenticationInfo } = await verifyAuthenticationResponse({ ... });
if (verified && authenticationInfo) {
  const { newCounter, credentialID } = authenticationInfo;
  dbAuthenticator.counter = authenticationInfo.newCounter;
  await updateCounterInDatabase({ credIDString: credentialID, newCounter });
}
```

---

#### [server] `AuthenticatorDevice.credentialID` is now a `Base64URLString`

Calls to `verifyAuthenticationResponse()` will need to be updated to encode the credential ID to a
base64url string:

**Before**

```ts
const verification = await verifyAuthenticationResponse({
  // ...
  authenticator: {
    // ...
    credentialID: credIDBytes,
  },
});
```

**After**

```ts
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const verification = await verifyAuthenticationResponse({
  // ...
  authenticator: {
    // ...
    credentialID: isoBase64URL.fromBuffer(credIDBytes),
  },
});
```

---

#### [server] `isoBase64URL.isBase64url()` is now called `isoBase64URL.isBase64URL()`

Note the capitalization change from "url" to "URL" in the method name. Update calls to this method
accordingly.

---

#### [server] `generateRegistrationOptions()` will now generate random user IDs

#### [browser] `user.id` is now treated like a base64url string in `startRegistration()`

#### [browser] `userHandle` is now treated like a base64url string in `startAuthentication()`

A random identifier will now be generated when a value is not provided for the now-optional `userID`
argument when calling `generateRegistrationOptions()`. This identifier will be **base64url-encoded
string of 32 random bytes**. RPs that wish to take advantage of this can **simply omit this
argument**.

Additionally, `startRegistration()` will base64url-decode `user.id` before calling WebAuthn. During
auth `startAuthentication()` will base64url-encode `userHandle` in the returned credential. This
should be a transparent change for RP's that simply feed **@simplewebauthn/server** options output
into the corresponding **@simplewebauthn/browser** methods.

However, RP's that wish to continue generating their own user identifiers will need to take
additional steps to ensure they get back user IDs in the expected format after authentication.

**Before (SimpleWebAuthn v9)**

```ts
// @simplewebauthn/server v9.x
const opts = generateRegistrationOptions({
  // ...
  userID: 'randomUserID',
});
```

```ts
// @simplewebauthn/browser v9.x
const credential = await startAuthentication(...);
sendToServer(credential);
```

```ts
// @simplewebauthn/server v9.x
const credential = await receiveFromBrowser();
console.log(
  credential.response.userhandle, // 'randomUserID'
);
```

**After (SimpleWebAuthn v10)**

```ts
// @simplewebauthn/server v10.x
import { isoUint8Array } from '@simplewebauthn/server/helpers';

const opts = generateRegistrationOptions({
  // ...
  userID: isoUint8Array.fromUTF8String('randomUserID'),
});
```

```ts
// @simplewebauthn/browser v10.x
const credential = await startAuthentication(...);
sendToServer(credential);
```

```ts
// @simplewebauthn/server v10.x
import { isoBase64URL } from '@simplewebauthn/server/helpers';

const credential = await receiveFromBrowser();
console.log(
  isoBase64URL.toUTF8String(credential.response.userhandle), // 'randomUserID'
);
```

---

#### [server] `isoBase64URL.toString()` and `isoBase64URL.fromString()` have been renamed

The method names have been updated to reflect the use of UTF-8 string encoding:

**Before:**

```ts
const foo = isoBase64URL.toString('...');
const bar = isoBase64URL.fromString('...');
```

**After:**

```ts
const foo = isoBase64URL.toUTF8String('...');
const bar = isoBase64URL.fromUTF8String('...');
```

---

#### [server] `rpID` is now a required argument when calling `generateAuthenticationOptions()`

Update calls to this method to specify the same `rpID` as passed into
`generateRegistrationOptions()`:

**Before**

```ts
  generateRegistrationOptions({ rpID: 'example.com', ... });
generateAuthenticationOptions();
```

**After**

```ts
  generateRegistrationOptions({ rpID: 'example.com', ... });
generateAuthenticationOptions({ rpID: 'example.com' });
```

## v9.0.3

### Packages

- @simplewebauthn/server@9.0.3

### Changes

- **[server]** Fixed
  `"Cannot find module 'cbor-x/index-no-eval' or its corresponding type declarations"` build errors
  when transpiling TypeScript projects using **@simplewebauthn/server**
  ([#521](https://github.com/MasterKale/SimpleWebAuthn/pull/521))

## v9.0.2

### Packages

- @simplewebauthn/server@9.0.2

### Changes

- **[server]** Improved support for Next.js Edge runtime
  ([#518](https://github.com/MasterKale/SimpleWebAuthn/pull/518), with thanks to @balazsorban44)

## v9.0.1

### Packages

- @simplewebauthn/browser@9.0.1
- @simplewebauthn/server@9.0.1
- @simplewebauthn/types@9.0.1

### Changes

- **[server]** Fixed an issue with use with CBOR handling in runtime environments that restrict use
  of `eval()` ([#511](https://github.com/MasterKale/SimpleWebAuthn/pull/511), with thanks to
  @Maronato)
- **[browser, types]** Monorepo version sync

## v9.0.0 - The one in which 11 characters were saved

### Packages

- @simplewebauthn/browser@9.0.0
- @simplewebauthn/server@9.0.0
- @simplewebauthn/types@9.0.0

### Changes

- **[types]** The `@simplewebauthn/typescript-types` package has been renamed to
  `@simplewebauthn/types` ([#508](https://github.com/MasterKale/SimpleWebAuthn/pull/508))

### Breaking Changes

- Any reference to `@simplwebauthn/typescript-types` will need to be replaced with the new package
  name `@simplewebauthn/types`:

**Before:**

```ts
import { ... } from '@simplwebauthn/typescript-types';
```

**After:**

```sh
$> npm uninstall @simplewebauthn/typescript-types
$> npm install -D @simplewebauthn/types
```

```ts
import { ... } from '@simplwebauthn/types';
```

## v8.3.7

### Packages

- @simplewebauthn/browser@8.3.7
- @simplewebauthn/server@8.3.7

### Changes

- **[browser]** The `WebAuthnError` class can now be imported from `@simplewebauthn/browser` for
  simpler error detection and handling when calling `startRegistration()` and
  `startAuthentication()` ([#505](https://github.com/MasterKale/SimpleWebAuthn/pull/505), with
  thanks to @zoontek)
- **[server]** The `COSEPublicKeyEC2`, `COSEPublicKeyOKP`, and `COSEPublicKeyRSA` types can now be
  imported from `@simplwebauthn/server/helpers` to help type possible return values from
  `decodeCredentialPublicKey()` ([#504](https://github.com/MasterKale/SimpleWebAuthn/pull/504), with
  thanks to @mmv08)
- **[server]** Custom challenge strings passed to `generateRegistrationOptions()` will now be
  treated as UTF-8 strings to align with the existing behavior of `generateAuthenticationOptions()`
  ([#507](https://github.com/MasterKale/SimpleWebAuthn/pull/507))

## v8.3.6

### Packages

- @simplewebauthn/server@8.3.6

### Changes

- **[server]** Updated dependencies to fix an issue with ASN.1 parsing when calling
  `verifyAuthenticationResponse()` ([#499](https://github.com/MasterKale/SimpleWebAuthn/pull/499))

## v8.3.5

### Packages

- @simplewebauthn/server@8.3.5

### Changes

- **[server]** Use of the Web Crypto API in edge runtimes has been improved
  ([#472](https://github.com/MasterKale/SimpleWebAuthn/pull/472))

## v8.3.4

### Packages

- @simplewebauthn/browser@.3.4
- @simplewebauthn/server@.3.4
- @simplewebauthn/typescript-types@.3.4

### Changes

- **[server]** The library will now try to use `globalThis.crypto` first before trying to import
  Node's `node:crypto` as a fallback ([#468](https://github.com/MasterKale/SimpleWebAuthn/pull/468))
- **[browser, types]** Version sync

## v8.3.3

### Packages

- @simplewebauthn/browser@8.3.3
- @simplewebauthn/server@8.3.3
- @simplewebauthn/typescript-types@8.3.3

### Changes

- **[server, types]** `deno vendor` will no longer error out because **typescript-types/src/dom.ts**
  is missing ([#466](https://github.com/MasterKale/SimpleWebAuthn/pull/466))
- **[server]** Authenticator data will now be preserved after bad CBOR encoding is detected and
  temporarily fixed when handling security key responses from Firefox
  ([#465](https://github.com/MasterKale/SimpleWebAuthn/pull/465))
- **[browser]** Version sync due to changes in **typescript-types**

## v8.3.2

### Packages

- @simplewebauthn/server@8.3.2

### Changes

- **[server]** The cbor-x dependency is now used without pulling in the Node-specific `stream` API
  for better Web API environment compatibility
  ([#455](https://github.com/MasterKale/SimpleWebAuthn/pull/455), with thanks to @Maronato)

## v8.3.1

### Packages

- @simplewebauthn/browser@8.3.1

### Changes

- **[browser]** Calling `startAuthentication(..., true)` to set up conditional UI will now require
  the `"webauthn"` value in an input's `autocomplete="..."` be either the only value or the last
  value ([#451](https://github.com/MasterKale/SimpleWebAuthn/pull/451))

## v8.3.0

### Packages

- @simplewebauthn/browser@8.3.0

### Changes

- **[browser]** The `WebAuthnAbortService` singleton can now be imported, with a `cancelCeremony()`
  method that can be called to manually cancel any active WebAuthn ceremonies. This can be used by
  developers building projects that use client-side routing to better control the behavior of their
  UX in response to router navigation events.
  ([#449](https://github.com/MasterKale/SimpleWebAuthn/pull/449))

## v8.2.1

### Packages

- @simplewebauthn/browser@8.2.1

### Changes

- **[browser]** `startRegistration()` will visibly warn in the browser console when a WebAuthn API
  method call errors out in a way that is likely due to a browser extension intercepting the API
  ([#447](https://github.com/MasterKale/SimpleWebAuthn/pull/447))

## v8.2.0

### Packages

- @simplewebauthn/browser@8.2.0
- @simplewebauthn/server@8.2.0

### Changes

- **[browser]** `startRegistration()` will no longer error out on registration responses generated
  by the 1Password browser extension ([#443](https://github.com/MasterKale/SimpleWebAuthn/pull/443),
  with thanks to @unix)
- **[browser]** Helper methods `base64URLStringToBuffer()` and `bufferToBase64URLString()` are now
  exported from `@simplewebauthn/browser`
  ([#444](https://github.com/MasterKale/SimpleWebAuthn/pull/444))
- **[server]** `verifyRegistrationResponse()` and `verifyAuthenticationResponse()` now accept a new
  `expectedType` argument that can be used to, for example, verify Secure Payment Confirmation
  responses ([#436](https://github.com/MasterKale/SimpleWebAuthn/pull/436), with thanks to
  @fabiancook)
- **[server]** Responses containing malformed authenticator data returned from Firefox 117 will no
  longer raise an error ([#441](https://github.com/MasterKale/SimpleWebAuthn/pull/441))

## v8.1.1

### Packages

- @simplewebauthn/server@8.1.1

### Changes

- **[server]** Debug logger output from `MetadataService` has been disabled
  ([#434](https://github.com/MasterKale/SimpleWebAuthn/pull/434))

## v8.1.0

### Packages

- @simplewebauthn/server@8.1.0

### Changes

- **[server]** The `expectedChallenge` argument for `verifyRegistrationResponse()` and
  `verifyAuthenticationResponse()` methods now also accept asynchronous methods
  ([#432](https://github.com/MasterKale/SimpleWebAuthn/pull/432), with thanks to @jordanbtucker)

## v8.0.2

### Packages

- @simplewebauthn/browser@8.0.2

### Changes

- **[browser]** The NPM package now targets ES2021 for support in older browsers like Safari 13.1
  ([#429](https://github.com/MasterKale/SimpleWebAuthn/pull/429))

## v8.0.1

### Packages

- @simplewebauthn/server@8.0.1

### Changes

- **[server]** Node projects with `"type": "module"` in their **package.json** will no longer error
  out when trying to use methods that leverage the Crypto APIs
  ([#428](https://github.com/MasterKale/SimpleWebAuthn/pull/428))

## v8.0.0 - Around the (ESM) World

This major release marks the completion of a long journey that started with the release of v7.0.0:
SimpleWebAuthn is now available for use in non-Node projects! 🎉

SimpleWebAuthn debuted in mid-2020 as a combination of libraries aiming to make WebAuthn simpler to
use across browsers and "NodeJS + CommonJS" applications. Since then NodeJS has evolved to gain ESM
support, and additional JavaScript and TypeScript runtimes have debuted that offer ESM-centric,
TypeScript-first alternatives while also implementing Web APIs to offer a more consistent and
capable execution environment for developers.

I've wanted to make this project available to developers using these Node alternatives to help them
get past some of WebAuthn's rough spots. Today I'm happy to announce that this goal has been
achieved! 😌

See the **Changes** below for more information, as well as additional information on breaking
changes made in this release.

### Packages

- @simplewebauthn/browser@8.0.0
- @simplewebauthn/server@8.0.0
- @simplewebauthn/typescript-types@8.0.0

### Changes

- **[server] [typescript-types]** SimpleWebAuthn can now also be used in runtimes other than Node.
  Deno is now a first-class runtime for this project alongside Node
  ([#425](https://github.com/MasterKale/SimpleWebAuthn/pull/425))
  - The following list of runtimes are officially supported:
    - (Existing) NodeJS using CommonJS
    - (Existing) NodeJS using ECMAScript Modules (ESM)
    - (New) Deno @ https://deno.land/x/simplewebauthn
  - The following list of runtimes are periodically tested but unofficially supported:
    - (New) CloudFlare Workers
    - (New) Bun
- **[browser]** Version sync

### Breaking Changes

- **[server]** `generateRegistrationOptions()` and `generateAuthenticationOptions()` are now
  asynchronous methods. Refactor calls to these methods to handle the `Promise` that's now returned
  in whatever way is appropriate for your project.
- **[server]** `generateChallenge()` (in `@simplewebauthn/server/helpers`) is now an asynchronous
  method. Refactor calls to this method to handle the `Promise` that's now returned in whatever way
  is appropriate for your project.

## v7.4.0

**Packages:**

- @simplewebauthn/browser@7.4.0
- @simplewebauthn/iso-webcrypto@7.4.0
- @simplewebauthn/server@7.4.0
- @simplewebauthn/typescript-types@7.4.0

**Changes:**

- **[browser] [typescript-types]** `AuthenticatorAttestationResponseJSON` now includes additional,
  optional `publicKeyAlgorithm`, `publicKey`, and `authenticatorData` convenience values that track
  JSON interface changes in WebAuthn L3 draft
  ([#400](https://github.com/MasterKale/SimpleWebAuthn/pull/400))
- **[iso-crypto]** Version sync
- **[server]** `verifyRegistrationResponse()` and `verifyAuthenticationResponse()` now return the
  matched origin and RP ID in their to output to help RP's that use the same verification logic with
  multiple origins and RP ID's understand where a response was generated and for which RP
  ([#415](https://github.com/MasterKale/SimpleWebAuthn/pull/415))
- **[typescript-types]** `"smart-card"` is now a recognized value for `AuthenticatorTransportFuture`
  ([#399](https://github.com/MasterKale/SimpleWebAuthn/pull/399))

## v7.3.1

**Packages:**

- @simplewebauthn/server@7.3.1

**Changes:**

- **[server]** The `AttestationStatement.size` property declaration is now more tolerant of older
  versions of TypeScript
- **[server]** Declared minimum supported TypeScript version of 4.4+

## v7.3.0

**Packages:**

- @simplewebauthn/server@7.3.0

**Changes:**

- **[server]** Improved signature verification of the latest FIDO MDS JWTs
  ([#390](https://github.com/MasterKale/SimpleWebAuthn/pull/390))

## v7.2.0

**Packages:**

- @simplewebauthn/browser@7.2.0
- @simplewebauthn/iso-webcrypto@7.2.0
- @simplewebauthn/server@7.2.0

**Changes:**

- **[server]** `generateRegistrationOptions()` defaults to `-8`, `-7`, and `-257` for supported
  public key algorithms ([#361](https://github.com/MasterKale/SimpleWebAuthn/pull/361))
- **[browser] [iso-webcrypto] [server]** Users will no longer need to also
  `npm install @simplewebauthn/typescript-types` to pull in type definitions when using these
  libraries ([#370](https://github.com/MasterKale/SimpleWebAuthn/pull/370))
- **[browser]** Errors raised by `startRegistration()` and `startAuthentication()` now include a
  `code` property to help programmatically detect identified errors. A new `cause` property is also
  populated that will always include the original error raised by the WebAuthn API call
  ([#367](https://github.com/MasterKale/SimpleWebAuthn/pull/367))
- **[browser]** Aborting conditional UI (i.e. calling `startAuthentication(..., true)` and then
  subsequently calling `startAuthentication()` for modal UI) will now throw an `AbortError` instead
  of a `string` ([#371](https://github.com/MasterKale/SimpleWebAuthn/pull/371))

## v7.1.0

**Packages:**

- @simplewebauthn/browser@7.1.0

**Changes:**

- **[browser]** `startRegistration()` and `startAuthentication()` now pass through all
  `NotAllowedError`'s without trying to interpret what caused them
  ([#353](https://github.com/MasterKale/SimpleWebAuthn/pull/353))

## v7.0.1

**Packages:**

- @simplewebauthn/browser@7.0.1
- @simplewebauthn/iso-webcrypto@7.0.1
- @simplewebauthn/server@7.0.1

**Changes:**

- **[server]** Update dependencies for better deduping in projects using **@simplewebauthn/server**
  ([#341](https://github.com/MasterKale/SimpleWebAuthn/pull/341))
- **[browser]** Version sync
- **[iso-webcrypto]** Version sync

## v7.0.0 - The one that sets the library loose

The highlight of this release is the rearchitecture of **@simplewebauthn/server** to start allowing
it to be used in more environments than Node. This was accomplished by refactoring the library
completely away from Node's `Buffer` type and `crypto` package, and instead leveraging `Uint8Array`
and the [WebCrypto Web API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) for all
cryptographic operations. This means that, hypothetically, this library can now also work in any
non-Node environment that provides access to the WebCrypto API on the global `crypto` object.

**Existing Node support is still first-class!** In fact because @simplewebauth/server still builds
to CommonJS it will continue to be tricky to incorporate the library in non-Node, ESM-only
environments that do not support CommonJS modules (whether natively, via a bundler, etc...) A future
update will attempt to fix this to offer better support for use in ESM-only projects with support
for WebCrypto (e.g. Deno).

**Please read all of the changes below!** There are significant breaking changes in this update and
additional information has been included to help adapt existing projects to the newest version of
these libraries.

**Packages:**

- @simplewebauthn/browser@7.0.0
- @simplewebauthn/server@7.0.0
- @simplewebauthn/typescript-types@7.0.0
- @simplewebauthn/iso-webcrypto@7.0.0

**Changes:**

- **[server]** A new "isomorphic" library architecture allows for use of this library in non-Node
  environments. In addition, the library now targets **Node 16** and above
  ([#299](https://github.com/MasterKale/SimpleWebAuthn/pull/299))
- **[server]** `@simplewebauthn/server/helpers` now includes several new helpers for working with
  WebAuthn-related data types that should work in all run times:
  - `isoCBOR` for working with CBOR-encoded values
  - `isoCrypto` for leveraging the WebCrypto API when working with various WebAuthn/FIDO2 data
    structures
  - `isoBase64URL` for encoding and decoding values into base64url (with optional base64 support)
  - `isoUint8Array` for working with `Uint8Array`s
  - `cose` for working with COSE-related methods and types
- **[server]** Certificate chains using self-signed X.509 root certificates now validate more
  reliably ([#310](https://github.com/MasterKale/SimpleWebAuthn/pull/310))
- **[server]** Code execution times for some common use cases are approximately 60-90% faster
  ([#311](https://github.com/MasterKale/SimpleWebAuthn/pull/311),
  [#315](https://github.com/MasterKale/SimpleWebAuthn/pull/315))
- **[iso-webcrypto]** This new library helps **@simplewebauthn/server** reference the WebCrypto API
  in more environments than Node. This package is available on NPM, but **it is not officially
  supported for use outside of @simplewebauthn/server!**

### Breaking Changes

- **[server]** The following values returned from `verifyRegistrationResponse()` are now a
  `Uint8Array` instead of a `Buffer`. They will need to be passed into `Buffer.from(...)` to convert
  them to `Buffer` if needed:
  - `aaguid`
  - `authData`
  - `clientDataHash`
  - `credentialID`
  - `credentialPublicKey`
  - `rpIdHash`
- **[server]** The following values returned from `verifyAuthenticationResponse()` are now a
  `Uint8Array` instead of a `Buffer`. They will need to be passed into `Buffer.from(...)` to convert
  them to `Buffer` if needed:
  - `credentialID`
- **[server]** The `isBase64URLString()` helper is now `isoBase64URL.isBase64url()`
- **[server]** The `decodeCborFirst()` helper is now `isoCBOR.decodeFirst()`
- **[server]** The `convertPublicKeyToPEM()` helper has been removed
- **[typescript-types] [server] [browser]** New JSON-serialization-friendly data structures added to
  the WebAuthn L3 spec have been preemptively mapped into this project. Some types, values, and
  methods have been refactored or replaced accordingly
  ([#320](https://github.com/MasterKale/SimpleWebAuthn/pull/320)):
  - The `RegistrationCredentialJSON` type has been replaced by the `RegistrationResponseJSON` type
  - The `AuthenticationCredentialJSON` type has been replaced by the `AuthenticationResponseJSON`
    type
  - `RegistrationCredentialJSON.transports` has been relocated into
    `RegistrationResponseJSON.response.transports` to mirror response structure in the WebAuthn spec
  - The `verifyRegistrationResponse()` method has had its `credential` argument renamed to
    `response`
  - The `verifyAuthenticationResponse()` method has had its `credential` argument renamed to
    `response`
- **[server]** `generateRegistrationOptions()` now marks user verification as `"preferred"` during
  registration and authentication (to reduce some user friction at the browser+authenticator level),
  and requires user verification during response verification. See below for refactor tips
  ([#307](https://github.com/MasterKale/SimpleWebAuthn/pull/307))

<details>
  <summary>Refactor Tips</summary>
  RP's implementing a second-factor flow with WebAuthn, where UV is not important (because username+password are provided before WebAuthn is leveraged for the second factor), should not require user verification when verifying responses:

### `verifyRegistrationResponse()`

**Before**

```js
const verification = await verifyRegistrationResponse({
  credential: attestationFIDOU2F,
  // ...
});
```

**After**

```js
const verification = await verifyRegistrationResponse({
  credential: attestationFIDOU2F,
  // ...
  requireUserVerification: false,
});
```

### `verifyAuthenticationResponse()`

**Before**

```js
const verification = await verifyAuthenticationResponse({
  credential: assertionResponse,
  // ...
});
```

**After**

```js
const verification = await verifyAuthenticationResponse({
  credential: assertionResponse,
  // ...
  requireUserVerification: false,
});
```

</details>

- **[server]** `generateRegistrationOptions()` now defaults to preferring the creation of
  discoverable credentials. See below for refactor tips
  ([#324](https://github.com/MasterKale/SimpleWebAuthn/pull/324))

<details>
  <summary>Refactor Tips</summary>
  RP's that do not require support for discoverable credentials from authenticators will need to update their calls to `generateRegistrationOptions()` accordingly:

### `generateRegistrationOptions()`

**Before**

```js
const options = generateRegistrationOptions({
  rpName: 'SimpleWebAuthn',
  rpID: 'simplewebauthn.dev',
  userID: '1234',
  userName: 'usernameHere',
});
```

**After**

```js
const options = generateRegistrationOptions({
  rpName: 'SimpleWebAuthn',
  rpID: 'simplewebauthn.dev',
  userID: '1234',
  userName: 'usernameHere',
  authenticatorSelection: {
    // See https://www.w3.org/TR/webauthn-2/#enumdef-residentkeyrequirement
    residentKey: 'discouraged',
  },
});
```

</details>

## v6.2.2

**Packages:**

- @simplewebauthn/browser@6.2.2
- @simplewebauthn/server@6.2.2

**Changes:**

- **[browser]** `browserSupportsWebAuthnAutofill()` no longer supports the old Chrome Canary way of
  testing for conditional UI support ([#298](https://github.com/MasterKale/SimpleWebAuthn/pull/298))
- **[server]** Version sync

## v6.2.1

**Packages:**

- @simplewebauthn/browser@6.2.1
- @simplewebauthn/server@6.2.1
- @simplewebauthn/testing@6.2.1
- @simplewebauthn/typescript-types@6.2.1

**Changes:**

- **[browser]** Multiple calls to `startRegistration()` and `startAuthentication()` will now more
  reliably cancel the preceding call ([#275](https://github.com/MasterKale/SimpleWebAuthn/pull/275))
- **[server]** Version sync
- **[testing]** Version sync
- **[typescript-types]** Version sync

## v6.2.0

**Packages:**

- @simplewebauthn/server@6.2.0

**Changes:**

- **[server]** The value of the user verification flag is now returned from
  `verifyAuthenticationResponse()` as `authenticationInfo.userVerified`, similar to how
  `verifyRegistrationResponse()` currently returns this value
  ([#263](https://github.com/MasterKale/SimpleWebAuthn/pull/263))

## v6.1.0

**Packages:**

- @simplewebauthn/server@6.1.0

**Changes:**

- **[server]** Improve support for requiring resident keys when targeting WebAuthn L1
  ([#259](https://github.com/MasterKale/SimpleWebAuthn/pull/259))
- **[server]** Encourage authenticators to produce Ed25519 credential keypairs when supported
  ([#261](https://github.com/MasterKale/SimpleWebAuthn/pull/261))

## v6.0.0 - The one with Ed25519 Support

This release also marks the return of the library's ability to pass FIDO Conformance! Adding Ed25519
signature verification (see below) finally allowed the library to pass all required tests, and
nearly all optional tests.

**Packages:**

- @simplewebauthn/browser@6.0.0
- @simplewebauthn/server@6.0.0
- @simplewebauthn/testing@6.0.0
- @simplewebauthn/typescript-types@6.0.0

**Changes:**

- **[server]** Signatures can now be verified with OKP public keys that use the Ed25519 curve and
  EDDSA algorithm ([#256](https://github.com/MasterKale/SimpleWebAuthn/pull/256))
- **[testing]** Version sync
- **[typescript-types]** Version sync

### Breaking Changes

- **[server]** `verifyAuthenticationResponse()` now returns
  `Promise<VerifiedAuthenticationResponse>` instead of `VerifiedAuthenticationResponse`
  ([#256](https://github.com/MasterKale/SimpleWebAuthn/pull/256))

Update your existing calls to `verifyAuthenticationResponse()` to handle the values resolved by the
promises, whether with `.then()` or `await` depending on your code structure:

**Before:**

```js
const verification = verifyAuthenticationResponse({
  // ...
});
```

**After:**

```js
const verification = await verifyAuthenticationResponse({
  // ...
});
```

- **[browser]** `browserSupportsWebauthn()` has been renamed to `browserSupportsWebAuthn()`
  ([#257](https://github.com/MasterKale/SimpleWebAuthn/pull/257))

Update calls to `browserSupportsWebauthn()` to capitalize the "A" in "WebAuthn":

**Before:**

```js
if (browserSupportsWebauthn()) {
  // ...
}
```

**After:**

```js
if (browserSupportsWebAuthn()) {
  // ...
}
```

## v5.4.5

**Packages:**

- @simplewebauthn/server@5.4.5

**Changes:**

- **[server]** Support FIDO Conformance user verification requirements
  ([#254](https://github.com/MasterKale/SimpleWebAuthn/pull/254))

To leverage these requirements (as might be the case for RP's seeking FIDO certification), update
your calls to `verifyAuthenticationResponse()` to **replace** `requireUserVerification` with the new
`advancedFIDOConfig.userVerification` option:

**Before:**

```ts
const verification = verifyAuthenticationResponse({
  // ...
  requireUserVerification: true,
});
```

**After**

```ts
const verification = verifyAuthenticationResponse({
  // ...
  advancedFIDOConfig: {
    // UserVerificationRequirement: 'required' | 'preferred' | 'discouraged'
    userVerification: 'required',
  },
});
```

Setting `advancedFIDOConfig.userVerification` to `'required'` will only require the `uv` flag to be
true; `up` flag may be `false`. Setting it to `'preferred'` or `'discouraged'` will allow both `up`
and `uv` to be `false` during verification.

- **[server]** Rename the `devicePublicKey` property on the
  `AuthenticationExtensionsAuthenticatorOutputs` type to `devicePubKey`
  ([#243](https://github.com/MasterKale/SimpleWebAuthn/pull/243); no one supports this yet so it's
  not a breaking change)

## v5.4.4

**Packages:**

- @simplewebauthn/server@5.4.4

**Changes:**

- **[server]** Enhance compliance with current FIDO conformance requirements
  ([#249](https://github.com/MasterKale/SimpleWebAuthn/pull/249),
  [#251](https://github.com/MasterKale/SimpleWebAuthn/pull/251))
- **[server]** Minor performance improvements
  ([#150](https://github.com/MasterKale/SimpleWebAuthn/pull/250))

## v5.4.3

**Packages:**

- @simplewebauthn/server@5.4.3

**Changes:**

- **[server]** Remove support for the following defunct FIDO metadata authentication algorithms:
  `"rsa_emsa_pkcs1_sha256_raw"`, `"rsa_emsa_pkcs1_sha256_der"`, `"sm2_sm3_raw"`
  ([#245](https://github.com/MasterKale/SimpleWebAuthn/pull/245))
- **[server]** Update remaining FIDO metadata constants to match v2.2 of the FIDO Registry of
  Predefined Values ([#244](https://github.com/MasterKale/SimpleWebAuthn/pull/244))

## v5.4.2

**Packages:**

- @simplewebauthn/server@5.4.2

**Changes:**

- **[server]** Add support for `"rsa_emsa_pkcs1_sha256_raw"` and `"rsa_emsa_pkcs1_sha256_der"`
  authentication algorithms in FIDO MDS metadata statements
  ([#241](https://github.com/MasterKale/SimpleWebAuthn/pull/241))

## v5.4.1

**Packages:**

- @simplewebauthn/browser@5.4.1
- @simplewebauthn/server@5.4.1

**Changes:**

- **[browser]** `"type": "module"` has been added to package.json to appease modern front end
  tooling that expects this value to be present when using the ESM build
  ([#237](https://github.com/MasterKale/SimpleWebAuthn/pull/237))
- **[server]** TPM attestation statement verification now properly verifies statements with ECC
  public area type ([#239](https://github.com/MasterKale/SimpleWebAuthn/pull/239))

## v5.4.0

**Packages:**

- @simplewebauthn/browser@5.4.0
- @simplewebauthn/server@5.4.0
- @simplewebauthn/typescript-types@5.4.0

**Changes:**

- **[server]** `verifyRegistrationResponse()` and `verifyAuthenticationResponse()` now return
  authenticator extension data upon successful verification as the new
  `authenticatorExtensionResults` property
  ([#230](https://github.com/MasterKale/SimpleWebAuthn/pull/230))
- **[browser]** Code quality improvements
- **[typescript-types]** Code quality improvements

## v5.3.0

**Packages:**

- @simplewebauthn/browser@5.3.0
- @simplewebauthn/server@5.3.0
- @simplewebauthn/typescript-types@5.3.0

**Changes:**

- **[browser]** `startAuthentication()` now accepts a second `useBrowserAutofill` boolean argument
  that sets up support for credential selection via a browser's autofill prompt (a.k.a. Conditional
  UI). The new `browserSupportsWebAuthnAutofill()` helper method can be used independently to
  determine when this feature is supported by the browser
  ([#214](https://github.com/MasterKale/SimpleWebAuthn/pull/214))
- **[browser]** `startRegistration()` and `startAuthentication()` will return a new
  `authenticatorAttachment` value when present that captures whether a cross-platform or platform
  authenticator was just used ([#221](https://github.com/MasterKale/SimpleWebAuthn/pull/221))
- **[typescript-types]** A new `PublicKeyCredentialFuture` interface has been added to define new
  properties currently defined in the WebAuthn L3 spec draft. These new values support the above new
  functionality until official TypeScript types are updated accordingly
  ([#214](https://github.com/MasterKale/SimpleWebAuthn/pull/214),
  [#221](https://github.com/MasterKale/SimpleWebAuthn/pull/221))
- **[typescript-types]** A new `"hybrid"` transport has been added to `AuthenticatorTransportFuture`
  while browsers migrate away from the existing `"cable"` transport for cross-device auth
  ([#222](https://github.com/MasterKale/SimpleWebAuthn/pull/222))

## v5.2.1

**Packages:**

- @simplewebauthn/browser@5.2.1
- @simplewebauthn/server@5.2.1
- @simplewebauthn/typescript-types@5.2.1

**Changes:**

- **[server]** `generateRegistrationOptions()` and `generateAuthenticationOptions()` will stop
  reporting typing errors for definitions of `excludeCredentials` and `allowCredentials` that were
  otherwise fine before v5.2.0 ([#203](https://github.com/MasterKale/SimpleWebAuthn/pull/203))
- **[typescript-types]** The new `AuthenticatorTransportFuture` and
  `PublicKeyCredentialDescriptorFuture` have been added to track changes to WebAuthn that outpace
  TypeScript's DOM lib typings
- **[browser]** Version sync

## v5.2.0

**Packages:**

- @simplewebauthn/browser@5.2.0
- @simplewebauthn/server@5.2.0
- @simplewebauthn/typescript-types@5.2.0

**Changes:**

- **[browser, typescript-types]** The new `"cable"` transport is now recognized as a potential value
  of the `AuthenticatorTransport` type
  ([#198](https://github.com/MasterKale/SimpleWebAuthn/pull/198))
- **[server]** `verifyRegistrationResponse()` and `verifyAuthenticationResponse()` now return
  `credentialDeviceType` and `credentialBackedUp` within `authenticatorInfo` as parsed values of two
  new flags being added to authenticator data. These response verification methods will also now
  throw an error when the invalid combination of these two flags
  (`credentialDeviceType: "singleDevice", credentialBackedUp: true`) is detected
  ([#195](https://github.com/MasterKale/SimpleWebAuthn/pull/195))
  - This feature supports detection of "multi-device credentials" gradually
    [coming to all major platform authenticator vendors](https://fidoalliance.org/world-password-day-had-a-good-run-now-were-celebrating-a-future-with-less-passwords/)
    later this year.

## v5.1.0

**Packages:**

- @simplewebauthn/browser@5.1.0
- @simplewebauthn/server@5.1.0

**Changes:**

- **[browser]** Custom errors raised when calling `startRegistration()` and `startAuthentication()`
  will now have the same `name` property as the original error
  ([#191](https://github.com/MasterKale/SimpleWebAuthn/pull/191))
- **[server]** Cleaned up code and added tests
  ([#192](https://github.com/MasterKale/SimpleWebAuthn/pull/192),
  [#193](https://github.com/MasterKale/SimpleWebAuthn/pull/193))

## v5.0.0 The one with more insights

**Packages:**

- @simplewebauthn/browser@5.0.0
- @simplewebauthn/server@5.0.0
- @simplewebauthn/testing@5.0.0
- @simplewebauthn/typescript-types@5.0.0

**Changes:**

- **[browser]** Most common WebAuthn errors that can occur when calling `startRegistration()` and
  `startAuthentication()` will now return descriptions with more specific insights into what went
  wrong ([#184](https://github.com/MasterKale/SimpleWebAuthn/pull/184))
- **[testing]** Version sync
- **[typescript-types]** Version sync

### Breaking Changes

- **[server]** The `fidoUserVerification` argument to `verifyAuthenticationResponse()` has been
  replaced with the simpler `requireUserVerification` boolean
  ([#181](https://github.com/MasterKale/SimpleWebAuthn/pull/181))

Previous values of `"required"` should specify `true` for this new argument; previous values of
`"preferred"` or `"discouraged"` should specify `false`:

**Before:**

```ts
const verification = verifyAuthenticationResponse({
  // ...snip...
  fidoUserVerification: 'required',
});
```

**After:**

```ts
const verification = verifyAuthenticationResponse({
  // ...snip...
  requireUserVerification: true,
});
```

## v4.4.0

**Packages:**

- @simplewebauthn/server@4.4.0

**Changes:**

- **[server]** Attestation statement verification involving FIDO metadata now correctly validates
  the credential public keypair algorithm against possible algorithms defined in the metadata
  statement.
- **[server]** The expired GlobalSign R2 root certificate for `"android-safetynet"` responses has
  been removed
- **[server]** Certificate path validation errors will now identify which part of the chain and
  which certificate has an issue
- **[server]** `verifyAuthenticationResponse()`'s `expectedChallenge` argument also accepts a
  function that accepts a Base64URL `string` and returns a `boolean` to run custom logic against the
  `clientDataJSON.challenge` returned by the authenticator (see v4.3.0 release notes for more info).

## v4.3.0

**Packages:**

- @simplewebauthn/server@4.3.0

**Changes:**

- **[server]** The `expectedChallenge` argument passed to `verifyRegistrationResponse()` can now be
  a function that accepts a Base64URL `string` and returns a `boolean` to run custom logic against
  the `clientDataJSON.challenge` returned by the authenticator. This allows for arbitrary data to be
  included in the challenge so it can be signed by the authenticator.

After generating registration options, the challenge can be augmented with additional data:

```js
const options = generateRegistrationOptions(opts);

// Remember the plain challenge
inMemoryUserDeviceDB[loggedInUserId].currentChallenge = options.challenge;

// Add data to be signed
options.challenge = base64url(JSON.stringify({
  actualChallenge: options.challenge,
  arbitraryData: 'arbitraryDataForSigning',
}));
```

Then, when invoking `verifyRegistrationResponse()`, pass in a method for `expectedChallenge` to
parse the challenge and return a `boolean`:

```js
const expectedChallenge = inMemoryUserDeviceDB[loggedInUserId].currentChallenge;

const verification = await verifyRegistrationResponse({
  expectedChallenge: (challenge: string) => {
    const parsedChallenge = JSON.parse(base64url.decode(challenge));
    return parsedChallenge.actualChallenge === expectedChallenge;
  },
  // ...
});
```

To retrieve the arbitrary data afterwards, use `decodeClientDataJSON()` afterwards to get it out:

```js
import { decodeClientDataJSON } from '@simplewebauthn/server/helpers';

const { challenge } = decodeClientDataJSON(response.clientDataJSON);
const parsedChallenge = JSON.parse(base64url.decode(challenge));
console.log(parsedChallenge.arbitraryData); // 'arbitraryDataForSigning'
```

## v4.2.0

**Packages:**

- @simplewebauthn/server@4.2.0

**Changes:**

- **[server]** The [debug](https://www.npmjs.com/package/debug) library has been incorporated to
  support logging output from the library's internal operations. Add the following environment
  variable to your application to view this output when using this library:

```
DEBUG=SimpleWebAuthn:*
```

The following logging scopes are defined in this release:

```
SimpleWebAuthn:MetadataService
```

See [PR #159](https://github.com/MasterKale/SimpleWebAuthn/pull/159) for a preview of logging
output.

## v4.1.0

**Packages:**

- @simplewebauthn/browser@4.1.0
- @simplewebauthn/server@4.1.0

**Changes:**

- **[browser]** `platformAuthenticatorIsAvailable()` now checks that WebAuthn is supported at all
  before attempting to query for the status of an available platform authenticator.
- **[server]** `MetadataService.initialize()` gained a new `verificationMode` option that can be set
  to `"permissive"` to allow registration response verification to continue when an unregistered
  AAGUID is encountered. Default behavior, that fails registration response verification, is
  represented by the alternative value `"strict"`; MetadataService continues to default to this more
  restrictive behavior.

## v4.0.0 - The one with some new names

A lot has happened to me since I first launched SimpleWebAuthn back in May 2020. My understanding of
WebAuthn has grown by leaps and bounds thanks in part to my representing Duo/Cisco in the W3C's
WebAuth Adoption Working Group. I'm now in a point in my life in which it's no longer sufficient to
think, "what's in SimpleWebAuthn's best interests?" Now, I have an opportunity to think bigger -
"what's in the **WebAuthn API**'s best interests?"

While early on I thought "attestation" and "assertion" were important names to WebAuthn, I've since
come to better appreciate
[the spec's efforts to encourage the use of "registration" and "authentication"](https://www.w3.org/TR/webauthn-2/#sctn-use-cases)
instead. **To that end I decided it was time to rename all of the project's various public methods
and types** to get as much as possible to use "registration" and "authentication" instead.

This release is one of the more disruptive because it affects everyone who's used SimpleWebAuthn to
date. The good news is that, while method and type names have changed, their capabilities remain the
same. Updating your code to this version of SimpleWebAuthn should only involve renaming existing
method calls and type annotations.

**Please take the time to read the entire changelog for this release!** There are a handful of new
features also included that users with advanced use cases will find helpful. **The simple use cases
of the library remain unchanged** - most new features are for power users who require extra scrutiny
of authenticators that interact with their website and are otherwise opt-in as needed.

**Packages:**

- @simplewebauthn/browser@4.0.0
- @simplewebauthn/server@4.0.0
- @simplewebauthn/typescript-types@4.0.0

**Changes:**

- **[browser]** A new (asynchronous) helper method `platformAuthenticatorIsAvailable()` has been
  added for detecting when hardware-bound authenticators like Touch ID, Windows Hello, etc... are
  available for use.
  [More info is available here.](https://simplewebauthn.dev/docs/packages/browser#platformauthenticatorisavailable)
- **[server]** The new `SettingsService` can be used to configure aspects of SimpleWebAuthn like
  root certs for enhanced registration response verification or for validating FIDO MDS BLOBs with
  MetadataService.
  [More info is available here](https://simplewebauthn.dev/docs/packages/server#settingsservice).
- **[server]** Known root certificates for the following attestation formats have been updated:
  `'android-key'`, `'android-safetynet'`, `'apple'`
- **[server]** A wide range of internal helper methods are now exported from
  `'@simplewebauthn/server/helpers'` (not a new package, but a subpath.) These methods can be used,
  for example, to process non-standard responses that are not officially part of the WebAuthn spec
  and thus unlikely to ever be supported by SimpleWebAuthn.
- **[server]** `MetadataService` now supports
  [FIDO Alliance Metadata Service version 3.0](https://fidoalliance.org/metadata/).

### Breaking Changes

- **[browser, server, typescript-types]** All methods and types that included "attestation" in the
  name have been renamed to use **"registration"** instead
- **[browser, server, typescript-types]** All methods and types that included "assertion" in the
  name have been renamed to use **"authentication"** instead.

> The quickest way to update your code is to try changing "attestation" to "registration" and
> "assertion" to "authentication" in the name of whatever method or type is no longer working and
> see if that fixes it (exceptions to this rule are called out with asterisks below.) If it doesn't,
> check out [PR #147](https://github.com/MasterKale/SimpleWebAuthn/pull/147) to see all of the
> renamed methods and types and try to cross-reference the original to see what it was renamed to.
>
> **Examples:**
>
> - `generateAttestationOptions()` -> **`generateRegistrationOptions()`**
> - `GenerateAttestationOptionsOpts` -> **`GenerateRegistrationOptionsOpts`**
> - `verifyAssertionResponse()` -> **`verifyAuthenticationResponse()`**
> - `VerifiedAttestation` -> **`VerifiedRegistrationResponse`** (*)
> - `VerifiedAssertion` -> **`VerifiedAuthenticationResponse`** (*)
> - `startAttestation()` -> **`startRegistration()`**
> - `startAssertion()` -> **`startAuthentication()`**
>
> **These examples are not a comprehensive list of all the renamed methods!** Rather these are
> examples of how method names were changed to try and eliminate "attestation" and "assertion" from
> the public API of both **@simplewebauthn/browser** and **@simplewebauthn/server**.

- **[server]** The `opts` argument for `MetadataService.initialize()` is now optional.
- **[server]** The `opts.mdsServers` argument for `MetadataService.initialize(opts)` is now a simple
  array of URL strings to FIDO Alliance MDSv3-compatible servers. If no value is specified then
  MetadataService will query the
  [official FIDO Alliance Metadata Service version 3.0](https://fidoalliance.org/metadata/).

> See [here](https://simplewebauthn.dev/docs/packages/server#metadataservice) for more information
> about the updated `MetadataService`.

- **[browser]** `supportsWebAuthn()` has been renamed to **`browserSupportsWebAuthn()`** in an
  effort to make the method convey a clearer idea of what supports WebAuthn.

## v3.1.0

**Packages:**

- @simplewebauthn/browser@3.1.0

**Changes:**

- **[browser]** The ES2018 bundle is now "main" in package.json. The `tslib` dependency for
  production is no longer necessary as transpilation to ES5 is now fully the responsibility of the
  framework implementing **@simplewebauthn/browser**.
  - The ES5 UMD build remains available for websites not leveraging a build pipeline.
- **[browser]** Linking to this package via **unpkg** now defaults to the ES2018 build. See
  browser's [README.md](./packages/browser/README.md) for information on how to link to the ES5
  build instead.

## v3.0.0 - The one with a legacy

This release is focused on updating @simplewebauthn/browser for better browser support out of the
box. Most projects will now pull in its (slightly larger) ES5 bundle to ensure maximum browser
compatibility, including older browsers in which WebAuthn will never be available. The ES2018 build
is still available for projects that only need to target newer browsers, but bundler configuration
changes must now be made to include it instead of the ES5 build.

**Packages:**

- @simplewebauthn/browser@3.0.0
- @simplewebauthn/server@3.0.0
- @simplewebauthn/typescript-types@3.0.0

**Changes:**

- **[browser]** Set default bundle to ES5 to support IE10+ and Edge Legacy
- **[browser]** `startAssertion()` no longer Base64URL-encodes `userHandle` string
- **[server]** Fix issue with Chrome (< v90) WebAuthn virtual authenticators
- **[server]** Update `jsrsasign` to `10.2.0` (see
  [GHSA-27fj-mc8w-j9wg](https://github.com/advisories/GHSA-27fj-mc8w-j9wg))
- **[typescript-types]** Update assertion JSON declarations as per `startAssertion()` fix

### Breaking Changes

- **[browser]** Projects targeting modern browsers may not wish to bundle the ES5 version due to its
  inclusion of various polyfills. See the updated "Building for Production" section of the
  [README.md](https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/README.md)
  for more info on how to pull in the ES2018 version instead.
- **[browser]** RPs with usernameless flows will no longer need to Base64URL-decode
  `response.userHandle` as returned from `startAssertion()`.

## v2.2.1

**Packages:**

- @simplewebauthn/browser@2.2.1
- @simplewebauthn/server@2.2.1

**Changes:**

- **[browser]** Adds support for older browsers (IE10/IE11, Edge Legacy, etc...) with additional
  build artifacts targeting ES5
  - See updated "Installation" and "Building for Production" sections of the
    [README.md](https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/browser/README.md)
- **[server]** Internal code cleanup

## v2.2.0

**Packages:**

- @simplewebauthn/server@2.2.0

**Changes:**

- **[server]** Export more TypeScript types for options and verification method inputs and outputs:

```ts
// Newly exported types
import type {
  GenerateAssertionOptionsOpts,
  GenerateAttestationOptionsOpts,
  VerifiedAssertion,
  VerifiedAttestation,
  VerifyAssertionResponseOpts,
  VerifyAttestationResponseOpts,
} from '@simplewebauthn/server';
```

## v2.1.0

**Packages:**

- @simplewebauthn/browser@2.1.0
- @simplewebauthn/server@2.1.0
- @simplewebauthn/typescript-types@2.1.0

**Changes:**

- **[browser]** **`startAttestation()`** and **`startAssertion()`** now include extension results as
  `clientExtensionResults` in their return value
- **[typescript-types]** Updated **`PublicKeyCredentialCreationOptionsJSON`** and
  **`PublicKeyCredentialRequestOptionsJSON`** types with new optional `extensions` property to
  support specifying WebAuthn extensions when calling `generateAttestationOptions()` and
  `generateAssertionOptions()`
- **[typescript-types]** Updated **`AttestationCredentialJSON`** and **`AssertionCredentialJSON`**
  types with new `clientExtensionResults` properties to contain output from WebAuthn's
  `credential.getClientExtensionResults()`
- **[server]** Version sync

## v2.0.0 - The one with -less and more Buffers

This major release includes improvements intended to make it easier to support **passwordless** and
**usernameless** WebAuthn flows. Additional information returned from attestation verification can
be used by RP's to further scrutinize the attestation now or in the future.

I also made the decision to reduce the amount of encoding from Buffer to Base64URL and decoding from
Base64URL to Buffer throughout the library. Verification methods now return raw **Buffers** so that
RP's are free to store and retrieve these values as they see fit without the library imposing any
kind of encoding overhead that may complicate storage in a database, etc...

**Packages:**

- @simplewebauthn/server@2.0.0
- @simplewebauthn/typescript-types@2.0.0
- @simplewebauthn/browser@2.0.0
- @simplewebauthn/testing@2.0.0

**Changes:**

- **[server]** See **Breaking Changes** below.
- **[typescript-types]** See **Breaking Changes** below
- **[browser]** Version sync
- **[testing]** Version sync

### Breaking Changes

- **[server]** The method **`verifyAttestationResponse()`** now returns a different data structure
  with additional information that RP's can use to more easily support passwordless and usernameless
  WebAuthn flows.
  - Additionally, `Buffer` values are now returned in place of previously-base64url-encoded values.
    This is intended to offer more flexibility in how these values are persisted without imposing an
    encoding scheme that may introduce undesirable overhead.

Before:

```ts
type VerifiedAttestation = {
  verified: boolean;
  userVerified: boolean;
  authenticatorInfo?: {
    fmt: ATTESTATION_FORMAT;
    counter: number;
    base64PublicKey: string;
    base64CredentialID: string;
  };
};
```

After:

```ts
type VerifiedAttestation = {
  verified: boolean;
  attestationInfo?: {
    fmt: ATTESTATION_FORMAT;
    counter: number;
    aaguid: string;
    credentialPublicKey: Buffer;
    credentialID: Buffer;
    credentialType: string;
    userVerified: boolean;
    attestationObject: Buffer;
  };
};
```

- **[server]** The method **`verifyAssertionResponse()`** now returns a different data structure to
  align with changes made to `verifyAttestationResponse()`.

Before:

```ts
type VerifiedAssertion = {
  verified: boolean;
  authenticatorInfo: {
    counter: number;
    base64CredentialID: string;
  };
};
```

After:

```ts
type VerifiedAssertion = {
  verified: boolean;
  assertionInfo: {
    credentialID: Buffer;
    newCounter: number;
  };
};
```

- **[server]** The `excludeCredentials` argument in **`generateAttestationOptions()`** now expects a
  `Buffer` type for a credential's `id` property. Previously `id` needed to be a `string`. Existing
  credential IDs stored in base64url encoding can be easily converted to Buffer with a library like
  `base64url`:

Before:

```ts
const options = generateAttestationOptions({
  // ...
  excludeCredentials: [{
    id: 'PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o',
    // ...
  }],
  // ...
});
```

After:

```ts
const options = generateAttestationOptions({
  // ...
  excludeCredentials: [{
    id: base64url.toBuffer('PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o'),
    // ...
  }],
  // ...
});
```

- **[server]** The `allowCredentials` argument in **`generateAssertionOptions()`** now expects a
  `Buffer` type for a credential's `id` property. Previously `id` needed to be a `string`. Existing
  credential IDs stored in base64url encoding can be easily converted to Buffer with a library like
  `base64url`:

Before:

```ts
const options = generateAssertionOptions({
  // ...
  allowCredentials: [{
    id: 'PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o',
    // ...
  }],
  // ...
});
```

After:

```ts
const options = generateAssertionOptions({
  // ...
  allowCredentials: [{
    id: base64url.toBuffer('PPa1spYTB680cQq5q6qBtFuPLLdG1FQ73EastkT8n0o'),
    // ...
  }],
  // ...
});
```

- **[typescript-types]** The `AuthenticatorDevice` type has been updated to expect `Buffer`'s for
  credential data. Naming of its properties have also been updated to help maintain consistency with
  naming in the WebAuthn spec:

Before:

```ts
type AuthenticatorDevice = {
  publicKey: Base64URLString;
  credentialID: Base64URLString;
  counter: number;
  transports?: AuthenticatorTransport[];
};
```

After:

```ts
type AuthenticatorDevice = {
  credentialPublicKey: Buffer;
  credentialID: Buffer;
  counter: number;
  transports?: AuthenticatorTransport[];
};
```

## v1.0.0 - The one that gets things out of "Beta"

**Packages:**

- @simplewebauthn/browser@1.0.0
- @simplewebauthn/server@1.0.0
- @simplewebauthn/testing@1.0.0
- @simplewebauthn/typescript-types@1.0.0

**Changes:**

- **[server]** Add support for multiple expected origins and RP IDs in `verifyAttestationResponse()`
  and `verifyAssertionResponse()`
- **[server]** Update `generateAttestationOptions()` to force legacy
  `authenticatorSelection.requireResidentKey` to `true` when `authenticatorSelection.residentKey` is
  `"required"` (as per L2 of the WebAuthn spec)
- **[typescript-types]** Update `AuthenticatorDevice` type with optional `transports` property
- **[browser]** Version sync
- **[testing]** Version sync

### Breaking Changes

There are no breaking changes in this release. Several recent minor changes presented an opportunity
to release a "v1.0". I'd received enough positive feedback about SimpleWebAuthn and noticed growing
usage which granted me the confidence to take advantage of this opportunity.

And perhaps this will give the project more legitimacy in the eyes of larger organizations wishing
to use it but waiting for the libraries to "get out of beta"...

## v0.10.6

**Packages:**

- @simplewebauthn/browser@0.10.6
- @simplewebauthn/server@0.10.6
- @simplewebauthn/testing@0.10.6

**Changes:**

- **[browser]** Refactor `toUint8Array()` for easier testing when integrated
- **[server]** Fix an unexpected build issue
- **[testing]** Publish package (stub)

## v0.10.5

**Packages:**

- @simplewebauthn/browser@0.10.5
- @simplewebauthn/server@0.10.5
- @simplewebauthn/typescript-types@0.10.5

**Changes:**

- **[server]** Make `allowCredentials` in `generateAssertionOptions()` optional
- **[server]** Support calling `generateAssertionOptions()` without any options
- **[browser]** Ignore "empty" values for `allowCredentials` before starting assertion
- **[typescript-types]** Unpin dependency versions

## v0.10.4

**Packages:**

- @simplewebauthn/browser@0.10.4
- @simplewebauthn/server@0.10.4
- @simplewebauthn/typescript-types@0.10.4

**Changes:**

- **[server]** Unpin dependency versions
- **[server]** Upgrade dependencies and devDependencies
- **[typescript-types]** Pull in TypeScript DOM lib types on build
- **[docs]** Upgrade TypeDoc for better API docs

## v0.10.3

**Packages:**

- @simplewebauthn/server@0.10.3

**Changes:**

- **[server]** Add optional `rpID` argument to `generateAssertionOptions()`

## v0.10.2

**Packages:**

- @simplewebauthn/server@0.10.2

**Changes:**

- **[server]** Update ASN.1 parsing libraries to latest releases

## v0.10.1

**Packages:**

- @simplewebauthn/server@0.10.1

**Changes:**

- **[server]** Pin third-party package versions

## v0.10.0 - The one you can use your face with

**Packages:**

- @simplewebauthn/browser@0.10.0
- @simplewebauthn/server@0.10.0
- @simplewebauthn/typescript-types@0.10.0

**Changes:**

- **[server]** Add support for "apple" attestations to support iOS Face ID and Touch ID
- **[server] [browser]** Enable specifying transports per credential for `allowCredentials` and
  `excludeCredentials`
- **[browser]** Return authenticator's transports (when available) as `transports` in response from
  `startAttestation()`
- **[typescript-types]** Add new `AuthenticatorAttestationResponseFuture` type for better typing of
  credential response methods (`getTransports()`, `getAuthenticatorData()`, etc...)

### Breaking Changes

- **[server]** Existing implementations of `generateAttestationOptions()` and
  `generateAssertionOptions()` must be updated to specify credentials with their own transports:

**generateAttestationOptions()**

```js
// OLD
const options = generateAttestationOptions({
  excludedCredentialIDs: devices.map((dev) => dev.credentialID),
  suggestedTransports: ['usb', 'ble', 'nfc', 'internal'],
});

// NEW
const options = generateAttestationOptions({
  excludeCredentials: devices.map((dev) => ({
    id: dev.credentialID,
    type: 'public-key',
    transports: dev.transports,
  })),
});
```

**generateAssertionOptions()**

```js
// OLD
const options = generateAssertionOptions({
  allowedCredentialIDs: user.devices.map((dev) => dev.credentialID),
  suggestedTransports: ['usb', 'ble', 'nfc', 'internal'],
});

// NEW
const options = generateAssertionOptions({
  allowCredentials: devices.map((dev) => ({
    id: dev.credentialID,
    type: 'public-key',
    transports: dev.transports,
  })),
});
```

## v0.9.1

**Packages:**

- @simplewebauthn/server@0.9.1

**Changes:**

- **[server]** Third-party package security update

## v0.9.0 - The one that knows RSA from EC2

**Packages:**

- @simplewebauthn/browser@0.9.0
- @simplewebauthn/server@0.9.0
- @simplewebauthn/typescript-types@0.9.0

**Changes:**

- **[server]** Add support for attestations and assertions containing RSA public keys.
- **[browser]** Version sync.
- **[typescript-types]** Version sync.

### Breaking Changes

- **[server]** `authenticatorInfo.base64PublicKey` returned by `verifyAttestationResponse()` is now
  the entire public key buffer instead of a pared down form of it (it's still returned
  base64url-encoded). This helps ensure support for existing public keys, as well as future public
  key formats that may be introduced in the future. **Public keys previously returned by this method
  must be upgraded via
  [this "upgrader" script](https://gist.github.com/MasterKale/175cb210b097632d7cd03fd409e2dfb3) to
  work with future assertions.**
- **[server]** The `serviceName` argument for `generateAttestationOptions()` has been renamed to
  `rpName`. This brings it in line with the existing `rpID` argument and maps more obviously to its
  respective property within the returned options.

## v0.8.2

**Packages:**

- @simplewebauthn/browser@0.8.2
- @simplewebauthn/server@0.8.2
- @simplewebauthn/typescript-types@0.8.2

**Changes:**

- **[server]** Return explicit defaults for `authenticatorSelection` in return value from
  `generateAttestationOptions()` for enhanced device compatibility.
- **[browser]** Version sync.
- **[typescript-types]** Version sync.

## v0.8.1

**Packages:**

- @simplewebauthn/server@0.8.1

**Changes:**

- **[server]** Stop filtering out algorithm ID's from `supportedAlgorithmIDs` when calling
  `generateAttestationOptions()`
- **[server]** Fix a bug when verifying TPM attestation extensions

## v0.8.0 - The one with better challenges

**Packages:**

- @simplewebauthn/browser@0.8.0
- @simplewebauthn/server@0.8.0
- @simplewebauthn/typescript-types@0.8.0

**Changes:**

- **[server]** The `challenge` parameter of `generateAttestationOptions()` and
  `generateAssertionOptions()` is now _optional_.
  - **When undefined** the library will generate a random challenge. This value will be
    base64url-encoded in preparation for transit to the front end.
  - **When defined** the value will be directly encoded to base64url in preparation for transit to
    the front end.
- **[browser]** `startAttestation()` and `startAssertion()` now convert the base64url-encoded
  `options.challenge` to a buffer before passing it to the authenticator.

### Breaking Changes

- **[server]** `verifyAttestationResponse()` and `verifyAssertionResponse()` now require the
  base64url-encoded challenge to be passed in as `expectedChallenge`:

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

- **[server]** Added support for specifying a custom array of COSE algorithm identifiers when
  calling `generateAttestationOptions()` and `verifyAttestationResponse()`
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

- **[server]** The return type of `verifyAttestationResponse()` changed from `boolean` to
  `Promise<boolean>`. This was necessary to support querying FIDO MDS for an authenticator metadata
  statement during attestation verification.
- **[server]** The optional `requireUserVerification` parameter of `verifyAssertionResponse()` has
  been replaced with the new optional `fidoUserVerification` parameter. This enables greater control
  over user verification when verifying assertions.

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

- **[server]** (BREAKING) Server's `verifyAttestationResponse()` and `verifyAssertionResponse()`
  methods now take a single arguments object.
- **[server]** These methods now include the ability to require user verification during attestation
  and assertion verification via the new `requireUserVerification` argument.

## v0.5.1

**Packages:**

- @simplewebauthn/typescript-types@0.5.1

**Changes:**

- **[typescript-types]** Re-export `AuthenticatorAttestationResponseJSON` and
  `AuthenticatorAssertionResponseJSON`

## v0.5.0 - The one where browser returns more info

**Packages:**

- @simplewebauthn/browser@0.5.0
- @simplewebauthn/server@0.5.0
- @simplewebauthn/typescript-types@0.5.0

**Changes:**

- **[browser]** (BREAKING) Refactor `startAttestation()` and `startAssertion()` to return more of
  the output from the `navigator.credentials` calls
- **[browser]** Replace `base64-js` dependency with internal functionality
- **[browser, server]** Standardize on use of Base64URL encoding when converting to and from JSON
- **[server]** (BREAKING) Remove references to "base64" from `generateAttestationOptions()` and
  `generateAssertionOptions()` by renaming the `excludedBase64CredentialIDs` and
  `allowedBase64CredentialIDs` to `excludedCredentialIDs` and `allowedCredentialIDs` respectively
- **[typescript-types]** (BREAKING) Migrate some non-shared typings into **server**
