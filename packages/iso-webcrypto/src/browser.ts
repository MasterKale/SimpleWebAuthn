/* eslint-disable @typescript-eslint/ban-ts-comment */
/* IMPORT */

import type { Crypto } from '@simplewebauthn/typescript-types';

/* MAIN */

/**
 * We're in a browser-like environment, `crypto` should be available globally whether in the DOM,
 * in a service worker, etc...
 */
// @ts-ignore
const WebCrypto: Crypto = crypto;

/* EXPORT */

export default WebCrypto;
