<!-- omit in toc -->
# @simplewebauthn/browser

![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@simplewebauthn/browser?style=for-the-badge&logo=npm)](https://www.npmjs.com/package/@simplewebauthn/browser)
![Browser Support](https://img.shields.io/badge/Browser-ES2018+-brightgreen?style=for-the-badge&logo=Mozilla+Firefox)

- [Installation](#installation)
  - [UMD](#umd)
- [Usage](#usage)

## Installation

This package is available on **npm**:

```sh
npm install @simplewebauthn/browser
```

It can then be imported into a project as usual:

```js
import SimpleWebAuthnBrowser from '@simplewebauthn/browser';
```

### UMD

This package can also be installed via **unpkg** by including the following script in your page's `<head>` element:

```html
<script src="https://unpkg.com/@simplewebauthn/browser/dist/simplewebauthn-browser.min.js"></script>
```

The library's methods will be available on the global `SimpleWebAuthnBrowser` object.

## Usage

Check out [the example's public/ folder](../../example/public/) for a practical implementation of this library.

Lower-level API documentation for the methods in this library is available [here](https://simplewebauthn.netlify.app/modules/_simplewebauthn_browser.html).
