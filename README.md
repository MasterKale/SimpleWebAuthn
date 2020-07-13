<!-- omit in toc -->
# SimpleWebAuthn Project
![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/search?q=simplewebauthn)

- [Overview](#overview)
- [Example](#example)
- [Philosophy](#philosophy)
- [Tested Devices](#tested-devices)
- [Development](#development)

## Overview

This monorepo contains two complimentary libraries to help reduce the amount of work needed to
incorporate WebAuthn into a website. The following packages are maintained here:

- [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/server)
- [@simplewebauthn/browser](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/browser)

An additional package is also included that contains shared TypeScript definitions:

- [@simplewebauthn/typescript-types](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/typescript-types/)

See these packages' READMEs for more specific implementation information.

**API Documentation**

In-depth API documentation for all of the packages in this project is available here: https://docs.simplewebauthn.dev/

## Example

For a practical guide to implementing these libraries, take a look at the [example project](https://github.com/MasterKale/SimpleWebAuthn/tree/master/example). It includes a single-file Express server and a few HTML files that, combined with the packages in this repo, are close to all it takes to get up and running with WebAuthn.

## Philosophy

WebAuthn is a browser API that enables the use of physical, cryptographically-secure hardware "authenticators" to provide stronger replacements to passwords or 2FA.

Website back ends that wish to leverage this technology must be set up to do two things:

1. Provide to the front end a specific collection of values that the hardware authenticator will understand for "registration" and "login".
2. Parse responses from a hardware authenticator.

Website front ends have their own part to play in the process:

1. Pass the server-provided values into `navigator.credentials.create()` and `navigator.credentials.get()` so the user can interact with their compatible authenticator.
2. Pass the authenticator's response returned from these methods back to the server.

On the surface, this is a relatively straightforward dance. Unfortunately the values passed into the `navigator.credentials` methods and the responses received from them make heavy use of `ArrayBuffer`'s which are difficult to transmit as JSON between front end and back end. Not only that, there are many complex ways in which authenticator responses must be parsed, and though finalized, [the W3C spec](https://w3c.github.io/webauthn/) is quite complex and is being expanded all the time.

**Enter SimpleWebAuthn.**

SimpleWebAuthn attempts to offer a developer-friendly pair of libraries that simplify the above dance. **@simplewebauthn/server** exports a small number of methods requiring a handful of simple inputs that pair with the two primary methods exported by **@simplewebauthn/browser**. No converting back and forth between `Uint8Array` (or was this supposed to be an `ArrayBuffer`...?) and `String`, no worrying about JSON compatibility - **SimpleWebAuthn takes care of it all!**

## Tested Devices

WebAuthn support is currently spotty, but getting better. Here are things I've tested that I know support WebAuthn and work fine with the SimpleWebAuthn example:

| OS      | Browser |                  Authenticator |
| :------ | :-----: | -----------------------------: |
| macOS   | Firefox | Yubikey Security Key NFC (USB) |
| macOS   | Chrome  |                       Touch ID |
| iOS     | Safari  | Yubikey Security Key NFC (NFC) |
| Android | Chrome  |            Fingerprint Scanner |
| Android | Firefox |                     Screen PIN |

The FIDO Alliance [maintains a list of what currently supports WebAuthn](https://fidoalliance.org/fido2/fido2-web-authentication-webauthn/). If "WebAuthn API" is green, that combination of browser and OS *should* work fine with SimpleWebAuthn. That said, SimpleWebAuthn isn't perfect, so pull requests are welcome!

## Development

After pulling down the code, set up dependencies:

```sh
$> npm install
$> npm run bootstrap
```

To run unit tests for all tracked lerna packages, run the following:

```sh
$> npx lerna run test
```

Running Jest in watch mode for a specific project requires the use of `lerna exec`:

```sh
$> npx lerna exec npm run test:watch --scope=@simplewebauthn/server
```
