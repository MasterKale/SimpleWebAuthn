import { webcrypto } from 'node:crypto';
// Silence some console output
// jest.spyOn(console, 'log').mockImplementation();
// jest.spyOn(console, 'debug').mockImplementation();
// jest.spyOn(console, 'error').mockImplementation();

/**
 * We can use this to test runtimes in which the WebCrypto API is available
 * on `globalThis.crypto`
 *
 * This shouldn't be needed anymore once we move support to Node 19+ See here:
 * https://nodejs.org/docs/latest-v19.x/api/webcrypto.html#web-crypto-api
 */
// Object.defineProperty(globalThis, 'crypto', {
//   get(){
//     return webcrypto;
//   },
// });
