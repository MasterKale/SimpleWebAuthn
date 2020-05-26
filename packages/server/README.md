<!-- omit in toc -->

# @simplewebauthn/server

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/server)
![node-lts (scoped)](https://img.shields.io/node/v/@simplewebauthn/server?style=for-the-badge&logo=Node.js)

- [Installation](#installation)
- [Usage - Coming Soon](#usage---coming-soon)
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

## Usage - Coming Soon

Check out [the example](../../example/index.js) for now until this section gets updated.

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
