# WebAuthntine Example

A fully-functional reference implementation of [@webauthntine/server](../packages/server) and [@webauthntine/browser](../packages/browser).

## Requirements

- Node v10.0.0+

### SSL Certificate

Websites that wish to leverage WebAuthn *must* be served over HTTPS, **including during development!**

Here's one technique for setting up SSL for a local dev instance:

1. Create a `dev` A-record in `yourdomain.com`'s DNS settings that points to `127.0.0.1`
2. Use EFF's [certbot](https://certbot.eff.org/) locally to generate a .crt and .key for that `dev` subdomain
3. Update `key` and `cert` passed into `https.createServer()` to point to your custom certificates

## Instructions

1. Set up your SSL certificates as above
2. Install dependencies with `npm install`
3. Start the server with `npm start`
4. Navigate to `https://dev.yourdomain.com`
