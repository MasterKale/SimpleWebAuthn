# WebAuthntine Project
[![lerna](https://img.shields.io/badge/maintained%20with-lerna-cc00ff.svg)](https://lerna.js.org/)

It's like FIDO2 and Constantine had a baby...I dunno either 🤷‍♂️

This monorepo contains two complimentary libraries to help reduce the amount of work needed to
incorporate WebAuthn into a website. The following libraries are maintained here:

- @webauthntine/server
- @webauthntine/browser

An additional package is also included containing shared TypeScript definitions:

- @webauthntine/typescript-typings

## Development

After pulling down the code, set up dependencies:

```sh
$> npm install
$> npx lerna bootstrap
```

To run unit tests for all tracked lerna packages, run the following:

```sh
$> npx lerna test
```

Running Jest in watch mode for a specific project requires the use of `lerna exec`:

```sh
$> npx lerna exec npm run test:watch --scope=@webauthntine/server
```
