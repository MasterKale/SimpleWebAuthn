# Handbook

Notes for myself that I don't want cluttering up the README

## Deployment Process

### Step 1: Determine which packages need to be published

```
npx lerna version --no-push
```

What packages need to be published?

1.
   - [ ] typescript-types
1.
   - [ ] browser
1.
   - [ ] server

### Step 2: Need to publish `typescript-types`?

```
pnpm run build:types && (cd packages/typescript-types/npm; pnpm publish)
```

### Step 3: Need to publish `browser`?

```
pnpm run build:browser && (cd packages/browser; pnpm publish)
```

### Step 4: Need to publish `server`?

1.
   - [ ] Make sure the correct version of `typescript-types` is on NPM
   - The `npm install` step that dnt performs while building the project pulls from NPM. The build
     will fail if the version of `typescript-types` specified in `mappings` in **build_npm.ts** is
     unavailable.

```
pnpm run build:server && (cd packages/server/npm; pnpm publish)
```
