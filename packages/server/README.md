# @simplewebauthn/server <!-- omit in toc -->

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/server)
[![JSR](https://jsr.io/badges/@simplewebauthn/server?style=for-the-badge)](https://jsr.io/@simplewebauthn/server)

- [Installation](#installation)
  - [Node LTS 22.x and higher](#node-lts-22x-and-higher)
  - [Deno v2.4.x and higher](#deno-v24x-and-higher)
- [Documentation](#documentation)
- [Supported Attestation Formats](#supported-attestation-formats)

## Installation

This package can be installed from **[NPM](https://www.npmjs.com/package/@simplewebauthn/server)**
and **[JSR](https://jsr.io/@simplewebauthn/server)**:

### Node LTS 22.x and higher

```sh
npm install @simplewebauthn/server
```

> NOTE: This project will aim to support Node LTS releases through their Active and Maintenance windows as tracked on [the Node.js Releases page](https://nodejs.org/en/about/previous-releases).

### Deno v2.4.x and higher

```sh
deno add jsr:@simplewebauthn/server
```

> NOTE: [Deno no longer has LTS releases to track after April 30, 2026](https://docs.deno.com/runtime/fundamentals/stability_and_releases/#long-term-support-(lts)). This project will aim to support Deno minor releases for up to one year after their release.

## Documentation

You can find in-depth documentation on this package here:
https://simplewebauthn.dev/docs/packages/server

## Supported Attestation Formats

SimpleWebAuthn supports
[all current WebAuthn attestation formats](https://w3c.github.io/webauthn/#sctn-defined-attestation-formats),
including:

- **Android Key**
- **Android SafetyNet**
- **Apple**
- **FIDO U2F**
- **Packed**
- **TPM**
- **None**
