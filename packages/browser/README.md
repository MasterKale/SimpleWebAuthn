<!-- omit in toc -->

# @simplewebauthn/browser

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/browser?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/browser)
![Browser Support](https://img.shields.io/badge/Browser-ES5+-brightgreen?style=for-the-badge&logo=Mozilla+Firefox)

- [@simplewebauthn/browser](#simplewebauthnbrowser)
  - [Installation](#installation)
    - [UMD](#umd)
      - [ES5](#es5)
      - [ES2018](#es2018)
  - [Usage](#usage)

## Installation

This package is available on **npm**:

```sh
npm install @simplewebauthn/browser
```

### UMD

This package can also be installed via **unpkg** by including the following script in your page's
`<head>` element. The library's methods will be available on the global **`SimpleWebAuthnBrowser`**
object.

> NOTE: The only difference between the two packages below is that the ES5 bundle includes
> TypeScript's `tslib` runtime code. This adds some bundle size overhead, but _does_ enable use of
> `supportsWebAuthn()` in older browsers to show appropriate UI when WebAuthn is unavailable.

#### ES5

If you need to support WebAuthn feature detection in deprecated browsers like IE11 and Edge Legacy,
include the `ES5` version:

```html
<script src="https://unpkg.com/@simplewebauthn/browser/dist/bundle/index.es5.umd.min.js"></script>
```

#### ES2018

If you only need to support modern browsers, include the `ES2018` version:

```html
<script src="https://unpkg.com/@simplewebauthn/browser"></script>
```

## Usage

You can find in-depth documentation on this package here:
https://simplewebauthn.dev/docs/packages/browser
