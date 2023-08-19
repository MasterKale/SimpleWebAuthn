import { build, BuildOptions, emptyDir } from 'https://deno.land/x/dnt@0.38.0/mod.ts';

const outDir = {
  publish: './npm',
  test: './npm-test',
} as const;
const lernaPackageJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('./package.json'),
);
const typesPackageJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('../typescript-types/npm/package.json'),
);

// Clear both build directories
await Promise.all([
  await emptyDir(outDir.publish),
  await emptyDir(outDir.test),
]);

/**
 * Maintain a separate build just for testing, as we need to shim crypto only
 * when test_runner.js runs to test the ESM and CJS output. The test environment
 * currently lacks `globalThis.crypto` and so shimming it is the only way to
 * get the tests to successfully execute. But we don't want the shim in the
 * build we post up to NPM so that the runtime's native Crypto can be used.
 *
 * See https://github.com/denoland/dnt/issues/181
 */
console.log('Building for testing...');
await build({
  entryPoints: getEntryPoints(),
  outDir: outDir.test,
  shims: {
    deno: {
      test: 'dev',
    },
    crypto: true,
  },
  test: true,
  // TODO: Re-enable if https://github.com/denoland/dnt/issues/331 can get resolved
  typeCheck: false,
  package: {
    name: 'for-testing-only',
    version: '0.0.0',
  },
  // Map from Deno package to NPM package for Node build
  mappings: getMappings(),
  // TypeScript tsconfig.json config
  compilerOptions: getCompilerOptions(),
});

console.log('Building for publishing...');
await build({
  entryPoints: getEntryPoints(),
  outDir: outDir.publish,
  shims: {},
  test: false,
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
      url: 'https://github.com/MasterKale/SimpleWebAuthn.git',
      directory: 'packages/server',
    },
    homepage: 'https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/server#readme',
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
  mappings: getMappings(),
  // TypeScript tsconfig.json config
  compilerOptions: getCompilerOptions(),
});

Deno.copyFileSync('LICENSE.md', `${outDir.publish}/LICENSE.md`);
Deno.copyFileSync('README.md', `${outDir.publish}/README.md`);

/**
 * Settings we can reuse across the two build configs
 */
function getEntryPoints(): BuildOptions['entryPoints'] {
  return [
    { name: '.', path: './src/index.ts' },
    { name: './helpers', path: './src/helpers/index.ts' },
  ];
}

function getMappings(): BuildOptions['mappings'] {
  return {
    'https://deno.land/x/b64@1.1.27/src/base64.js': {
      name: '@hexagon/base64',
      version: '^1.1.27',
    },
    'https://deno.land/x/cbor@v1.5.2/index.js': {
      name: 'cbor-x',
      version: '^1.5.2',
    },
    'https://esm.sh/v131/debug@4.3.4/denonext/debug.mjs': {
      name: 'debug',
      version: '^4.3.4',
    },
    'https://esm.sh/v131/@types/debug@4.1.8/index.d.ts': {
      name: '@types/debug',
      version: '^4.1.8',
    },
    'https://esm.sh/v131/cross-fetch@4.0.0/es2021/cross-fetch.mjs': {
      name: 'cross-fetch',
      version: '^4.0.0',
    },
    'https://esm.sh/v131/@peculiar/asn1-schema@2.3.6/denonext/asn1-schema.mjs': {
      name: '@peculiar/asn1-schema',
      version: '^2.3.6',
    },
    'https://esm.sh/v131/@peculiar/asn1-x509@2.3.6/es2021/asn1-x509.mjs': {
      name: '@peculiar/asn1-x509',
      version: '^2.3.6',
    },
    'https://esm.sh/v131/@peculiar/asn1-ecc@2.3.6/es2021/asn1-ecc.mjs': {
      name: '@peculiar/asn1-ecc',
      version: '^2.3.6',
    },
    'https://esm.sh/v131/@peculiar/asn1-rsa@2.3.6/es2021/asn1-rsa.mjs': {
      name: '@peculiar/asn1-rsa',
      version: '^2.3.6',
    },
    'https://esm.sh/v131/@peculiar/asn1-android@2.3.6/es2021/asn1-android.mjs': {
      name: '@peculiar/asn1-android',
      version: '^2.3.6',
    },
    // Mapping for '../../typescript-types/src/index.ts' in deps.ts
    '../typescript-types/src/index.ts': {
      name: '@simplewebauthn/typescript-types',
      version: `^${typesPackageJSON.version}`,
    },
  };
}

function getCompilerOptions(): BuildOptions['compilerOptions'] {
  return {
    lib: ['ES2021'],
  };
}
