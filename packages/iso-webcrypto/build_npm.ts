import { build, emptyDir } from 'https://deno.land/x/dnt@0.38.0/mod.ts';

const outDir = './npm';
const lernaPackageJSON: { version: string } = JSON.parse(await Deno.readTextFile('./package.json'));

await emptyDir(outDir);

await build({
  entryPoints: [
    { name: '.', path: './src/index.ts' },
  ],
  outDir,
  shims: {
    deno: 'dev',
  },
  test: false,
  // TODO: Re-enable if https://github.com/denoland/dnt/issues/331 can get resolved
  // typeCheck: false,
  // package.json values
  package: {
    name: '@simplewebauthn/iso-webcrypto',
    version: lernaPackageJSON.version,
    description: "A small library for accessing a runtime's WebCrypto API",
    license: 'MIT',
    author: 'Matthew Miller <matthew@millerti.me>',
    repository: {
      type: 'git',
      url: 'https://github.com/MasterKale/SimpleWebAuthn.git',
      directory: 'packages/iso-webcrypto',
    },
    homepage: 'https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/iso-webcrypto#readme',
    publishConfig: {
      access: 'public',
    },
    bugs: {
      url: 'https://github.com/MasterKale/SimpleWebAuthn/issues',
    },
    keywords: [
      'typescript',
      'isomorphic',
      'webcrypto',
      'browser',
      'node',
    ],
  },
  // Map from Deno package to NPM package for Node build
  mappings: {
    // Mapping for '../../typescript-types/src/index.ts' in deps.ts
    '../typescript-types/src/index.ts': {
      name: '@simplewebauthn/typescript-types',
      version: '^7.4.0',
    },
  },
  // TypeScript tsconfig.json config
  compilerOptions: {
    lib: ['ES2021'],
  },
});

// Deno.copyFileSync('LICENSE', 'npm/LICENSE');
Deno.copyFileSync('README.md', `${outDir}/README.md`);
