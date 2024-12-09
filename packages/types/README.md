# @simplewebauthn/types <!-- omit in toc -->

TypeScript typings for **@simplewebauthn/server** and **@simplewebauthn/browser**.

> NOTE: This package was formerly published as **@simplewebauthn/types**

## Including these types in other packages

The types in this package are codegen'd into **@simplewebauthn/browser** and
**@simplewebauthn/server** so that the types are within those packages. When changes are made to the
typings here, run the following command to copy them into the other packages:

```sh
deno task codegen
```

Commit the copied-over code as well so that changes to them are tracked just like any other change
to their codebases.
