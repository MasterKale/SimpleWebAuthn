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
  entryPoints: [
    { name: '.', path: './src/index.ts' },
    { name: './helpers', path: './src/helpers/index.ts' },
  ],
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
    name: '@simplewebauthn/server',
    version: denoJSON.version,
    description: 'SimpleWebAuthn for Servers',
    license: 'MIT',
    author: 'Matthew Miller <matthew@millerti.me>',
    repository: {
      type: 'git',
      url: 'git+https://github.com/MasterKale/SimpleWebAuthn.git',
      directory: 'packages/server',
    },
    homepage: 'https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/server#readme',
    publishConfig: {
      access: 'public',
    },
    engines: {
      node: '>=20.0.0',
    },
    bugs: {
      url: 'https://github.com/MasterKale/SimpleWebAuthn/issues',
    },
    keywords: [
      'typescript',
      'webauthn',
      'passkeys',
      'fido',
      'node',
    ],
    typesVersions: {
      '*': {
        '.': [
          'esm/index.d.ts',
        ],
        'helpers': [
          'esm/helpers/index.d.ts',
        ],
      },
    },
    dependencies: {
      // Deno workspaces maps this identifier locally, make sure it's defined in the NPM package
      '@simplewebauthn/types': `^${typesDenoJSON.version}`,
    },
  },
  // Map from Deno package to NPM package for Node build
  mappings: {},
  // TypeScript tsconfig.json config
  compilerOptions: {
    lib: ['ES2021'],
  },
});

Deno.copyFileSync('LICENSE.md', `${outDir}/LICENSE.md`);
Deno.copyFileSync('README.md', `${outDir}/README.md`);
