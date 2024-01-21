# Install root dependencies without trying to link workspace packages
pnpm install --ignore-workspace
# Build types so server can build
pnpm run build:types --skip-nx-cache
# If we can't run tests on a fresh pull then it might mean we need to refresh the Deno lock file
pnpm run test:server --skip-nx-cache
# If we can build server then the repo is probably ready for dev
pnpm run build:server --skip-nx-cache
# Link all the workspace packages as usual with a standard install
pnpm install
