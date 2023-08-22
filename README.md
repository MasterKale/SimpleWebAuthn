# SimpleWebAuthn Project <!-- omit in toc -->

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/search?q=simplewebauthn)

- [Overview](#overview)
- [Installation](#installation)
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

In-depth documentation for all of the packages in this project is available here:
https://simplewebauthn.dev/docs/

## Installation

These packages are all available on **npm** for use in **Node LTS 16.x** projects and supports
**both CommonJS and [ECMAScript modules (ESM)](https://nodejs.org/api/esm.html#enabling)**:

```sh
npm install @simplewebauthn/browser
npm install @simplewebauthn/server
npm install @simplewebauthn/typescript-types
```

The **server** and **typescript-types** packages are also available for import into **Deno v1.33.x**
projects from **deno.land/x**:

```ts
import {...} from 'https://deno.land/x/simplewebauthn/deno/server.ts';
import type {...} from 'https://deno.land/x/simplewebauthn/deno/typescript-types.ts';
```

## Example

For a practical guide to implementing these libraries, take a look at the
[example project](https://github.com/MasterKale/SimpleWebAuthn/tree/master/example). It includes a
single-file Express server and a few HTML files that, combined with the packages in this repo, are
close to all it takes to get up and running with WebAuthn.

## Development

Install the following before proceeding:

- **Node.js 18.x**
- **Deno 1.36.x**
- **pnpm 8.6.x**

After pulling down the code, set up dependencies:

```sh
$> pnpm install
```

To run unit tests for all workspace packages, use the `test` series of scripts:

```sh
# Run All tests
$> pnpm run test
# Run an individual package's tests
$> pnpm run test:browser
$> pnpm run test:server
```

Tests can be run in watch mode with the `dev` series of scripts:

```sh
$> pnpm run dev:browser
$> pnpm run dev:server
```
