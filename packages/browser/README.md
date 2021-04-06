<!-- omit in toc -->

# @simplewebauthn/browser

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/browser?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/browser)
![Browser Support](https://img.shields.io/badge/Browser-ES2018+-brightgreen?style=for-the-badge&logo=Mozilla+Firefox)

- [Installation](#installation)
    - [UMD](#umd)
        - [ES5](#es5)
        - [ES2018](#es2018)
- [Usage](#usage)
- [Build your application](#build-your-application)
    - [ES5 with Webpack](#es5-with-webpack)
    - [ES5 with Rollup](#es5-with-rollup)

## Installation

This package is available on **npm**:

```sh
npm install @simplewebauthn/browser
```

### UMD

This package can also be installed via **unpkg** by including the following script in your page's `<head>` element.

#### ES5

To use it in old browsers, you can include the `ES5` version:

```html

<script src="https://unpkg.com/@simplewebauthn/browser/dist/es5/index.umd.min.js"></script>
```

#### ES2018

To use it in modern browsers, you can include the `ES2018` version:

```html

<script src="https://unpkg.com/@simplewebauthn/browser/dist/es2018/index.umd.min.js"></script>
```

The library's methods will be available on the global `SimpleWebAuthnBrowser` object.

## Usage

You can find in-depth documentation on this package here: https://simplewebauthn.dev/docs/packages/browser

## Build your application

We provide you with two versions for this library: `ES2018` and `ES5`.

The `ES2018` version can be used in all **modern browsers** with a source code of your application in `Typescript` or
in `Javascript` without having to make a modification during the build process.

For the `ES5` version, you can include it in your application either in `Typescript` or in `Javascript` but you will
have to make sure you have the right file when building your application. We will detail this point a little below.

This version also requires the presence of `tslib` in order to function correctly.

You will see during the installation of this library that the dependency exists in `peer`. If you develop your
application in `Typescript`, `tslib` will be **automatically** installed while if your application is developed
in `Javascript`, you will then have to install it **yourself** by adding it in your **dependencies** of
the `package.json`.

### ES5 with Webpack

If you are using `Webpack` to build your application, you must make sure that you have as `target` the `web` value which
is the **default one** and nothing else will have to be done but if you have changed it, you will therefore have to indicate which files must be resolved as
indicated [here](https://webpack.js.org/configuration/resolve/#resolvemainfields)

The `ES5` version of this library is defined in the `browser` entry of the `package.json` which gives the following
configuration to put in your `webpack.config` file:

```js
module.exports = {
    //...
    resolve: {
        mainFields: [ 'browser', 'module', 'main' ],
    },
};
```

You can add all the other values you want but the most important is to have the value `browser` first to be sure that
the `ES5` version of this library is taken into account.

### ES5 with Rollup

If you are using `Rollup` to build your application, you must use
the `@rollup/plugin-node-resolve` [plugin](https://github.com/rollup/rollup-plugin-node-resolve#usage) to resolve the
dependency to the correct format of this library.

The `ES5` version of this library is defined in the `browser` entry of the `package.json` which gives the following
configuration to put in your `rollup.config` file:

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

You can add all the other values you want but the most important is to have the value `browser` first to be sure that
the `ES5` version of this library is taken into account.
