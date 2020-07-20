# SimpleWebAuthn Example

A fully-functional reference implementation of **@simplewebauthn/server** and **@simplewebauthn/browser**.

## Requirements

- Node v10.0.0+

### SSL Certificate

Websites that wish to leverage WebAuthn _must_ be served over HTTPS, **including during development!**

Here's one technique for setting up SSL for a local dev instance:

1. [Install mkcert](https://github.com/FiloSottile/mkcert#installation) as per its instructions
2. Run `mkcert -install` to initialize mkcert
3. Generate SSL certificates for localhost:

> ./example/ $> **mkcert -key-file localhost.key -cert-file localhost.crt localhost**

## Instructions

1. Set up your SSL certificates as above
2. Install dependencies with `npm install`
3. Start the server with `npm start`
4. Navigate to https://localhost
