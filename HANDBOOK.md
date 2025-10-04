# Handbook

Notes for myself that I don't want cluttering up the README

## Deployment Process

### Step 0: Things you might have missed

#### Did you update to a newer version of **Deno**?

Run this first to update **packages/types/dom.ts** then commit the changes:

```
deno task codegen:types
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

### Step 4: Create a git tag for the chosen version

Create a tag on HEAD for the new version number.

### Step 5: Push up `HEAD` to `origin`

Don't forget to push up the new tag to `origin` too!

### Step 6: Publish packages

#### Need to publish @simplewebauthn/browser?

Navigate to https://github.com/MasterKale/SimpleWebAuthn/actions/workflows/publishBrowser.yml and
**Run workflow** against **master**.

#### Need to publish @simplewebauthn/server?

Navigate to https://github.com/MasterKale/SimpleWebAuthn/actions/workflows/publicServer.yml and
**Run workflow** against **master**.
