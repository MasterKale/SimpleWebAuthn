<!-- omit in toc -->

# @simplewebauthn/browser

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/browser?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/browser)
[![JSR](https://jsr.io/badges/@simplewebauthn/browser?style=for-the-badge)](https://jsr.io/@simplewebauthn/browser)
![Browser Support](https://img.shields.io/badge/Browser-ES5+-brightgreen?style=for-the-badge&logo=Mozilla+Firefox)

- [@simplewebauthn/browser](#simplewebauthnbrowser)
  - [Installation](#installation)
    - [Node LTS 20.x and higher](#node-lts-20x-and-higher)
    - [Deno v1.43 and higher](#deno-v143-and-higher)
    - [UMD](#umd)
      - [ES5](#es5)
      - [ES2021](#es2021)
  - [Usage](#usage)

## Installation

This package can be installed from **NPM**, **JSR**, or **deno.land/x**:

### Node LTS 20.x and higher

```sh
$ npm install @simplewebauthn/browser @simplewebauthn/types
```

```sh
$ npx jsr add @simplewebauthn/browser @simplewebauthn/types
```

### Deno v1.43 and higher

```sh
$ deno add jsr:@simplewebauthn/browser jsr:@simplewebauthn/types
```

```sh
$ deno add npm:@simplewebauthn/browser npm:@simplewebauthn/types
```

```ts
import {...} from 'https://deno.land/x/simplewebauthn/deno/browser.ts';
import type {...} from 'https://deno.land/x/simplewebauthn/deno/types.ts';
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

#### ES2021

If you only need to support modern browsers, include the `ES2021` version:

```html
<script src="https://unpkg.com/@simplewebauthn/browser"></script>
```

## Usage

You can find in-depth documentation on this package here:
https://simplewebauthn.dev/docs/packages/browser
