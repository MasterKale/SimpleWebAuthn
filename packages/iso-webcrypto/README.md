# @simplewebauthn/iso-webcrypto

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/iso-webcrypto?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/iso-webcrypto)

A small library for accessing a runtime's WebCrypto API. Supports browsers, and Node projects using ESM and/or CommonJS.

**This library is not officially supported for use outside of [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn)!**

## Install

```sh
npm install --save @simplewebauthn/iso-webcrypto
```

## Usage

```ts
import WebCrypto from '@simplewebauthn/iso-webcrypto';

WebCrypto.randomUUID (); // => '43e16416-7a2a-4c00-b2e8-1ea7a57adfb9'
```

## Acknowledgements

Thank you to Fabio Spampinato and their [tiny-webcrypto](https://github.com/fabiospampinato/tiny-webcrypto) project that all but solves the issue of isomorphic WebCrypto use across browsers and Node. I forked that project and made this one to add in support for Node libraries written in TypeScript that transpile to CommonJS modules.
