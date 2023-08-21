# Simple imports for Deno projects

These **.ts** files enable shorter imports of the various packages available in this monorepo when
importing SimpleWebAuthn from https://deno.land/x/simplewebauthn.

## Installation

For example, to import the **server** or **typescript-types** packages into your Deno project, add
the following to your **deps.ts** file:

```ts
import {
  // ...
} from 'https://deno.land/x/simplewebauthn/deno/server.ts';

import {
  // ...
} from 'https://deno.land/x/simplewebauthn/deno/typescript-types.ts';
```
