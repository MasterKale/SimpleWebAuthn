import { build, emptyDir } from 'https://deno.land/x/dnt@0.40.0/mod.ts';

const outDir = './npm';

const lernaPackageJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('./package.json'),
);
const typesPackageJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('../types/npm/package.json'),
);

await emptyDir(outDir);

await build({
  entryPoints: [
    { name: '.', path: './src/index.ts' },
    { name: './helpers', path: './src/helpers/index.ts' },
  ],
  importMap: './deno.jsonc',
  outDir,
  shims: {
    deno: {
      test: 'dev',
    },
  },
  // TODO: Re-enable if https://github.com/denoland/dnt/issues/331 can get resolved
  typeCheck: false,
  // package.json values
  package: {
    name: '@simplewebauthn/server',
    version: lernaPackageJSON.version,
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
  },
  // Map from Deno package to NPM package for Node build
  mappings: {
    // Mapping for '../../types/src/index.ts' in deps.ts
    '../types/src/index.ts': {
      name: '@simplewebauthn/types',
      version: `^${typesPackageJSON.version}`,
    },
  },
  // TypeScript tsconfig.json config
  compilerOptions: {
    lib: ['ES2021'],
  },
});

Deno.copyFileSync('LICENSE.md', `${outDir}/LICENSE.md`);
Deno.copyFileSync('README.md', `${outDir}/README.md`);
