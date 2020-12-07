<!-- omit in toc -->
# SimpleWebAuthn Project
![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/search?q=simplewebauthn)

- [Overview](#overview)
- [Example](#example)
- [Development](#development)

## Overview

This monorepo contains two complimentary libraries to help reduce the amount of work needed to
incorporate WebAuthn into a website. The following packages are maintained here:

- [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/server)
- [@simplewebauthn/browser](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/browser)

An additional package is also included that contains shared TypeScript definitions:

- [@simplewebauthn/typescript-types](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/typescript-types/)

See these packages' READMEs for more specific implementation information.

**API Documentation**

In-depth documentation for all of the packages in this project is available here: https://simplewebauthn.dev/docs/

## Example

For a practical guide to implementing these libraries, take a look at the [example project](https://github.com/MasterKale/SimpleWebAuthn/tree/master/example). It includes a single-file Express server and a few HTML files that, combined with the packages in this repo, are close to all it takes to get up and running with WebAuthn.

## Development

After pulling down the code, set up dependencies:

```sh
$> npm install
$> npm run bootstrap
```

To run unit tests for all tracked lerna packages, run the following:

```sh
$> npx lerna run test
```

Running Jest in watch mode for a specific project requires the use of `lerna exec`:

```sh
$> npx lerna exec npm run test:watch --scope=@simplewebauthn/server
```

