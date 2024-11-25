# [DEPRECATED] deno.land/x support

Importing SimpleWebAuthn packages from `"https://deno.land/x/simplewebauthn/..."` URLs is no longer
supported. Please use Deno's native support for JSR imports instead.

## Example

**Before:**

```ts
import { generateAuthenticationOptions } from 'https://deno.land/x/simplewebauthn/deno/server.ts';
```

**After:**

```ts
import { generateAuthenticationOptions } from 'jsr:@simplewebauthn/server';
```

Alternatively, use `deno add` to install them from **[JSR](https://jsr.io/@simplewebauthn)**:

```sh
# Deno v1.42 and higher
deno add jsr:@simplewebauthn/server
```

```ts
import { generateAuthenticationOptions } from '@simplewebauthn/server';
```
