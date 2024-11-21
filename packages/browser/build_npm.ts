import { build, emptyDir } from '@deno/dnt';

const outDir = './npm';

const denoJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('./deno.jsonc'),
);
const typesDenoJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('../types/deno.jsonc'),
);

await emptyDir(outDir);

await build({
  entryPoints: ['./src/index.ts'],
  outDir,
  importMap: './deno.jsonc',
  shims: {
    deno: {
      test: 'dev',
    },
  },
  // TODO: Re-enable if https://github.com/denoland/dnt/issues/331 can get resolved
  typeCheck: false,
  // TODO: Re-enable if https://github.com/denoland/dnt/issues/430 can get resolved
  test: false,
  // package.json values
  package: {
    name: '@simplewebauthn/browser',
    version: denoJSON.version,
    description: 'SimpleWebAuthn for Browsers',
    license: 'MIT',
    author: 'Matthew Miller <matthew@millerti.me>',
    repository: {
      type: 'git',
      url: 'git+https://github.com/MasterKale/SimpleWebAuthn.git',
      directory: 'packages/browser',
    },
    homepage: 'https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/browser#readme',
    publishConfig: {
      access: 'public',
    },
    bugs: {
      url: 'https://github.com/MasterKale/SimpleWebAuthn/issues',
    },
    keywords: [
      'typescript',
      'webauthn',
      'passkeys',
      'fido',
      'umd'
    ],
    dependencies: {
      // Deno workspaces maps this identifier locally, make sure it's defined in the NPM package
      '@simplewebauthn/types': `^${typesDenoJSON.version}`,
    }
  },
  // Map from Deno package to NPM package for Node build
  mappings: {},
  // TypeScript tsconfig.json config
  compilerOptions: {
    lib: ['ES2022', 'DOM'],
  },
});

Deno.copyFileSync('LICENSE.md', `${outDir}/LICENSE.md`);
Deno.copyFileSync('README.md', `${outDir}/README.md`);

// TODO: Use dnt output as Rollup input to generate a UMD bundle
// See https://rollupjs.org/javascript-api/
