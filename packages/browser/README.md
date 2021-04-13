<!-- omit in toc -->

# @simplewebauthn/browser

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/browser?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/browser)
![Browser Support](https://img.shields.io/badge/Browser-ES5+-brightgreen?style=for-the-badge&logo=Mozilla+Firefox)

- [@simplewebauthn/browser](#simplewebauthnbrowser)
  - [Installation](#installation)
    - [UMD](#umd)
      - [ES2018](#es2018)
      - [ES5](#es5)
  - [Usage](#usage)
  - [Building for Production](#building-for-production)
    - [ES2018](#es2018-1)
    - [ES5](#es5-1)
      - [Webpack support](#webpack-support)
      - [Rollup support](#rollup-support)

## Installation

This package is available on **npm**:

```sh
npm install @simplewebauthn/browser
```

### UMD

This package can also be installed via **unpkg** by including the following script in your page's `<head>` element. The library's methods will be available on the global **`SimpleWebAuthnBrowser`** object.

> NOTE: The only difference between the two packages below is that the ES5 bundle includes TypeScript's `tslib` runtime code. This adds some bundle size overhead, but _does_ enable use of `supportsWebAuthn()` in older browsers to show appropriate UI when WebAuthn is unavailable.

#### ES2018

If you only need to support modern browsers, include the `ES2018` version:

```html

<script src="https://unpkg.com/@simplewebauthn/browser/dist/es2018/index.umd.min.js"></script>
```

#### ES5

If you need to support WebAuthn feature detection in deprecated browsers like IE11 and Edge Legacy, include the `ES5` version:

```html

<script src="https://unpkg.com/@simplewebauthn/browser/dist/es5/index.umd.min.js"></script>
```

## Usage

You can find in-depth documentation on this package here: https://simplewebauthn.dev/docs/packages/browser

## Building for Production

Two unbundled versions of this library are offered for your convenience, one targeting `ES2018` and a second targeting `ES5`.

### ES2018

The `ES2018` version is suitable for use when only **modern browsers** need to be supported. TypeScript and JavaScript codebases alike can import and use this library without any special build configuration considerations.

### ES5

The `ES5` version can also be used in both TypeScript and JavaScript codebases. However, you will need to ensure that your bundler pulls in the ES5 version of the library when building your application!

You will also need to ensure that the `tslib` dependency gets pulled into your build artifact:

- If you are authoring your application in TypeScript then this package will be **automatically** included so long as your **tsconfig.json** sets `"target": "ES5"`.
- If your application is written in Javascript then you will need to install this package **manually** by adding it to `dependencies` in your project's **package. json**:

```sh
$> npm install tslib
```

#### Webpack support

If your Webpack config's `"target"` is set to `"web"` ([the default value](https://webpack.js.org/configuration/target/)) then you're done - Webpack will pull in the ES5 build from the `"browser"` property in @simplewebauthn/browser's **package.json**.

If you've set a different value for `"target"`, though, then you'll need to indicate additional files for WebPack to resolve via the [`"resolve.mainFields"`](https://webpack.js.org/configuration/resolve/#resolvemainfields) property in your Webpack config:

```js
module.exports = {
    //...
    resolve: {
        mainFields: [ 'browser', 'module', 'main' ],
    },
};
```

`'browser'` must come first in the list to ensure that the `ES5` version of this library is bundled. Additional values can be added afterwards as needed.

#### Rollup support

The [`@rollup/plugin-node-resolve`](https://github.com/rollup/rollup-plugin-node-resolve#usage) plugin can be added to your Rollup config to read in the `browser` entry from @simplewebauthn/browser's **package.json**:

```js
// rollup.config.js
import resolve from 'rollup-plugin-node-resolve';

export default {
    // input: ...
    // output: ...
    plugins: [
        //...
        resolve({ mainFields: [ 'browser', 'module', 'main' ] }),
    ]
}
```

`'browser'` must come first in the list to ensure that the `ES5` version of this library is bundled. Additional values can be added afterwards as needed.
