# Handbook

Notes for myself that I don't want cluttering up the README

## Deployment Process

### Step 0: Things you might have missed

#### Did you update to a newer version of **Deno**?

Run this first to update **packages/types/dom.ts** then commit the changes:

```
(cd packages/types; deno task extract-dom-types)
```

### Step 1: Determine which packages need to be published

Run this command to determine which packages need entries in CHANGELOG.md:

```
deno task version
```

### Step 2: Update package versions

Update `"version"` in the following **deno.json** files for each package that needs a new release:

- **@simplewebauthn/browser**: [packages/browser/deno.json](./packages/browser/deno.json)
- **@simplewebauthn/server**: [packages/server/deno.json](./packages/server/deno.json)

Continue using your best judgement on what an appropriate new version number should be.

Commit these changes.

### Step 3: Update CHANGELOG.md

Add entries to CHANGELOG.md for the packages determined in the step above.

Commit these changes.

### Step 4: Publish packages

The following commands can be run from the root of the monorepo to build the respective package,
then **publish it to both [NPM](https://www.npmjs.com/search?q=%40simplewebauthn) and
[JSR](https://jsr.io/@simplewebauthn)**.

#### Need to publish @simplewebauthn/browser?

```
deno task publish:browser
```

#### Need to publish @simplewebauthn/server?

```
deno task publish:server
```

### Step 5: Create a git tag for the chosen version

Create a tag on HEAD for the new version number.

### Step 6: Push up `HEAD` to `origin`

Don't forget to push up the latest changes to `origin` when everything's been published!
