# Handbook

Notes for myself that I don't want cluttering up the README

## Deployment Process

### Step 0: Things you might have missed

#### Did you update the version of `"typescript"` in the monorepo's root **package.json** file?

Run this first to update **packages/types/dom.ts** then commit the changes:

```
(cd packages/types; pnpm run extract-dom-types)
```

### Step 1: Determine which packages need to be published

Run this command, **but cancel out the first time!** Use it to determine which packages need entries
in CHANGELOG.md:

```
pnpm run update-version
```

### Step 2: Update CHANGELOG.md

Add entries to CHANGELOG.md for the packages determined in the step above.

### Step 3: Update package versions

Re-run Step 1, **but go all the way through with it this time** so that the latest changes have an
entry in the CHANGELOG that gets bundled with the release:

```
pnpm run update-version
```

### Step 4: Need to publish `types`?

```
pnpm run publish:types
```

### Step 5: Need to publish `browser`?

```
pnpm run publish:browser
```

### Step 6: Need to publish `server`?

1.
   - [ ] Make sure the correct version of `types` is on NPM
   - The `npm install` step that dnt performs while building the project pulls from NPM. The build
     will fail if the version of `types` specified in `mappings` in **build_npm.ts** is unavailable.

```
pnpm run publish:server
```

### Step 7: Push up `HEAD` to `origin`

Don't forget to push up the latest changes to `origin` when everything's been published!
