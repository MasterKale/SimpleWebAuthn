<!-- omit in toc -->
# @simplewebauthn/server

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/server)
![node-lts (scoped)](https://img.shields.io/node/v/@simplewebauthn/server?style=for-the-badge&logo=Node.js)

- [Installation](#installation)
- [Usage](#usage)
- [Supported Attestation Formats](#supported-attestation-formats)

## Installation

This package is available on **npm**:

```sh
npm install @simplewebauthn/server
```

It can then be imported into a Node project as usual:

```js
// ESModule
import SimpleWebAuthnServer from '@simplewebauthn/server';
// CommonJS
const SimpleWebAuthnServer = require('@simplewebauthn/server');
```

## Usage

Check out [the example's index.js](../../example/index.js) for a practical implementation of this library.

Lower-level API documentation for the methods in this library is available [here](https://docs.simplewebauthn.dev/modules/_simplewebauthn_server.html).


## Supported Attestation Formats

SimpleWebAuthn can verify the following attestation formats:

- `fido-u2f`
- `packed`
  - Supported Certificates
    - `X5C`
    - `COSE - EC2`
    - `COSE - RSA` (code is present but needs further testing)
    - `COSE - OKP` (code is present but needs further testing)
- `android-safetynet`
- `none`
