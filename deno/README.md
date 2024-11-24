# [DEPRECATED] deno.land/x support

Importing SimpleWebAuthn packages from `"https://deno.land/x/simplewebauthn/..."` URLs is no longer
supported. Please use `deno add` to install them from **[JSR](https://jsr.io/@simplewebauthn)**
instead:

```sh
# Deno v1.42 and higher
$ deno add jsr:@simplewebauthn/...
```

These packages can also be imported from
**[NPM](https://www.npmjs.com/search?q=%40simplewebauthn)**:

```sh
# Deno v1.46 and higher
$ deno add npm:@simplewebauthn/...
```
