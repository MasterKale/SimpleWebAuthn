# @simplewebauthn/server <!-- omit in toc -->

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/server)

- [Installation](#installation)
  - [Node LTS 20.x or higher](#node-lts-20x-or-higher)
  - [Deno v1.43.x or higher](#deno-v143x-or-higher)
- [Usage](#usage)
- [Supported Attestation Formats](#supported-attestation-formats)

## Installation

### Node LTS 20.x or higher

This package can be installed from **NPM** (with support for **both CommonJS and
[ECMAScript modules (ESM)](https://nodejs.org/api/esm.html#enabling)** projects) or **JSR**:

```sh
$ npm install @simplewebauthn/server
```

```sh
$ npx jsr add @simplewebauthn/server
```

### Deno v1.43.x or higher

It is also available for import into Deno projects from **deno.land/x** or **JSR**:

```ts
import {...} from 'https://deno.land/x/simplewebauthn/deno/server.ts';
```

```sh
$ deno add jsr:@simplewebauthn/server
```

## Usage

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
