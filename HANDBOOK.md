# Handbook

Notes for myself that I don't want cluttering up the README

## Deployment Process

### Step 0: Things you might have missed

#### Did you update the version of `"typescript"` in the monorepo's root **package.json** file?

Run this first to update **packages/typescript-types/dom.ts** then commit the changes:

```
(cd packages/typescript-types; pnpm run extract-dom-types)
```

### Step 1: Determine which packages need to be published

Run this command, **but cancel out the first time!** Use it to determine which packages need entries
in CHANGELOG.md!

```
pnpm run update-version
```

What packages need to be published?

1.
   - [ ] typescript-types
1.
   - [ ] browser
1.
   - [ ] server

Add entries to CHANGELOG.md, then re-run the command but go all the way through with it so that the
latest changes have an entry in the CHANGELOG that gets bundled with the release.

### Step 2: Need to publish `typescript-types`?

```
pnpm run publish:types
```

### Step 3: Need to publish `browser`?

```
pnpm run publish:browser
```

### Step 4: Need to publish `server`?

1.
   - [ ] Make sure the correct version of `typescript-types` is on NPM
   - The `npm install` step that dnt performs while building the project pulls from NPM. The build
     will fail if the version of `typescript-types` specified in `mappings` in **build_npm.ts** is
     unavailable.

```
pnpm run publish:server
```

### Step 5: Push up `HEAD` to `origin`

Don't forget to push up the latest changes to `origin` when everything's been published!
