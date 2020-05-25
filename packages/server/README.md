<!-- omit in toc -->

# @webauthntine/server

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@webauthntine/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@webauthntine/server)
![node-lts (scoped)](https://img.shields.io/node/v/@webauthntine/server?style=for-the-badge&logo=Node.js)

- [Installation](#installation)
- [Usage - Coming Soon](#usage---coming-soon)
- [Supported Attestation Formats](#supported-attestation-formats)

## Installation

This package is available on **npm**:

```sh
npm install @webauthntine/server
```

It can then be imported into a Node project as usual:

```js
// ESModule
import WebAuthntineServer from '@webauthntine/server';
// CommonJS
const WebAuthntineServer = require('@webauthntine/server');
```

## Usage - Coming Soon

Check out [the example](../../example/index.js) for now until this section gets updated.

## Supported Attestation Formats

WebAuthntine can verify the following attestation formats:

- `fido-u2f`
- `packed`
  - Supported Certificates
    - `X5C`
    - `COSE - EC2`
    - `COSE - RSA` (code is present but needs further testing)
    - `COSE - OKP` (code is present but needs further testing)
- `android-safetynet`
- `none`
