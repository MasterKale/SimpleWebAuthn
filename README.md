# SimpleWebAuthn Project <!-- omit in toc -->

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/search?q=simplewebauthn)

- [Overview](#overview)
- [Installation](#installation)
- [Sponsors](#sponsors)
- [Example](#example)
- [Contributions](#contributions)
- [Development](#development)

## Overview

This monorepo contains two complimentary libraries to help reduce the amount of work needed to
incorporate WebAuthn into a website. The following packages are maintained here:

- [@simplewebauthn/server](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/server)
- [@simplewebauthn/browser](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/browser)

An additional package is also included that contains shared TypeScript definitions:

- [@simplewebauthn/types](https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/types/)

See these packages' READMEs for more specific implementation information.

**API Documentation**

In-depth documentation for all of the packages in this project is available here:
https://simplewebauthn.dev/docs/

## Installation

These packages are all available on **npm** for use in **Node LTS 20.x** projects and supports
**both CommonJS and [ECMAScript modules (ESM)](https://nodejs.org/api/esm.html#enabling)**:

```sh
npm install @simplewebauthn/browser
npm install @simplewebauthn/server
npm install @simplewebauthn/types
```

The **server** and **types** packages are also available for import into **Deno v1.33.x** projects
from **deno.land/x**:

```ts
import {...} from 'https://deno.land/x/simplewebauthn/deno/server.ts';
import type {...} from 'https://deno.land/x/simplewebauthn/deno/types.ts';
```

## Sponsors

Thank you very much to those who sponsor my work. Your contributions help keep the open-source dream
alive 🙇‍♂️

Interested in sponsoring this project? See here for more info:
https://github.com/sponsors/MasterKale

### 🌟 Platinum Sponsor <!-- omit from toc -->

<p class="sponsor-logo">
  <a href="https://a0.to/signup/simplewebauthn">
    <img src="https://github.com/user-attachments/assets/82bd296f-81c9-455f-b561-29119bd941c3" width="270" height="101" alt="Auth0 by Okta" />
    <br />
    <em>Simple Authentication. Make login our problem. Not yours.</em>
  </a>
</p>

### 🏅 Gold Sponsor <!-- omit from toc -->

<p class="sponsor-logo">
  <a href="https://www.authsignal.com">
    <img src="https://github.com/user-attachments/assets/475e8759-bb1a-4614-b3f9-b38002b11f34" width="270" height="63" alt="Authsignal" />
    <br />
    <em>Simple, drop-in passkeys and MFA as a Service</em>
  </a>
</p>

## Example

For a practical guide to implementing these libraries, take a look at the
[example project](https://github.com/MasterKale/SimpleWebAuthn/tree/master/example). It includes a
single-file Express server and a few HTML files that, combined with the packages in this repo, are
close to all it takes to get up and running with WebAuthn.

## Contributions

The SimpleWebAuthn project is not currently open to external contributions.

Please [submit an Issue](https://github.com/MasterKale/SimpleWebAuthn/issues/new/choose) and fill
out the provided template with as much information as possible if you have found a bug in need of
fixing.

You can also [submit an Issue](https://github.com/MasterKale/SimpleWebAuthn/issues/new/choose) to
request new features, or to suggest changes to existing features.

## Development

Install the following before proceeding:

- **Node 20.x**
- **Deno v1.46.x**
- **pnpm 9.12.x**

After pulling down the code, set up dependencies:

```sh
$> pnpm run bootstrap-monorepo
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
