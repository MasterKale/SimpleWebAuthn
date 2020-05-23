# WebAuthntine Project
![WebAuthn](https://img.shields.io/badge/WebAuthn-Simplified-blueviolet?style=for-the-badge&logo=WebAuthn)
[![npm (scoped)](https://img.shields.io/npm/v/@webauthntine/server?style=for-the-badge&logo=npm)](https://www.npmjs.com/search?q=webauthntine)

This monorepo contains two complimentary libraries to help reduce the amount of work needed to
incorporate WebAuthn into a website. The following packages are maintained here:

- [@webauthntine/server](./packages/server/)
- [@webauthntine/browser](./packages/browser)

An additional package is also included that contains shared TypeScript definitions:

- [@webauthntine/typescript-types](./packages/typescript-types/)

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
$> npx lerna exec npm run test:watch --scope=@webauthntine/server
```
