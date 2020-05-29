# ATTENTION

This folder contains a slightly-modified version of `typedoc-plugin-external-module-name@3.1.0`

This folder exists because of a perfect storm of issues with TypeDoc package versioning:

I'm using `typedoc@next` because it's the only version of TypeDoc that supports "--mode library" (see https://github.com/TypeStrong/typedoc/pull/1184), which is capable of generating awesome documentation despite this being a more complex monorepo project.

The **typedoc-plugin-external-module-name** plugin (see https://github.com/christopherthielen/typedoc-plugin-external-module-name) was incorporated because it made it easy to rename package names in the docs to follow an easier-to-read naming convention versus what TypeDoc was generating.

The original plugin as available on NPM is written with branching logic in `typedocVersionCompatibility.js > removeTags()` that checks for TypeDoc's version to be able to support removing tags from comments in a backwards-compatible manner.

`typedoc@next` is version `0.17.0-3`, which semver coerces to "0.17.0". This causes `removeTags()` to throw an error saying:

```
TypeError: comment.removeTags is not a function
```

**The reality is that this version of TypeDoc is actually still a 0.16.x version of the library**, so this plugin fails because `removeTags()` isn't available on `comment`'s available will 0.17.0.

To get docs hosting working, I've decided to temporarily host a modified version of this plugin in this repo until TypeDoc gets proper support for a "library" rendering mode. [It's pretty high up the priority list for whenever v0.18.0 drops](https://github.com/TypeStrong/typedoc/issues/1266) so hopefully this won't have to stick around for long...
