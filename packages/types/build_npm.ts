import { build, emptyDir } from '@deno/dnt';

import denoJSON from './deno.json' with { type: 'json' };


const outDir = './npm';

await emptyDir(outDir);

await build({
  entryPoints: ['./src/index.ts'],
  outDir,
  shims: {},
  // Keeping declarations in a single types/ directory to mimic the original file structure
  declaration: 'separate',
  test: false,
  // package.json values
  package: {
    name: '@simplewebauthn/types',
    version: denoJSON.version,
    description: 'TypeScript types used by the @simplewebauthn series of libraries',
    license: 'MIT',
    author: 'Matthew Miller <matthew@millerti.me>',
    repository: {
      type: 'git',
      url: 'git+https://github.com/MasterKale/SimpleWebAuthn.git',
      directory: 'packages/types',
    },
    homepage: 'https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/types#readme',
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
      'types',
    ],
  },
});

Deno.copyFileSync('LICENSE.md', `${outDir}/LICENSE.md`);
Deno.copyFileSync('README.md', `${outDir}/README.md`);
