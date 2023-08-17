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
  declaration: 'separate',
  test: false,
  // TODO: Re-enable if https://github.com/denoland/dnt/issues/331 can get resolved
  typeCheck: false,
  // package.json values
  package: {
    name: '@simplewebauthn/typescript-types',
    version: lernaPackageJSON.version,
    description: 'TypeScript types used by the @simplewebauthn series of libraries',
    license: 'MIT',
    author: 'Matthew Miller <matthew@millerti.me>',
    repository: {
      type: 'git',
      url: 'https://github.com/MasterKale/SimpleWebAuthn.git',
      directory: 'packages/typescript-types',
    },
    homepage: "https://github.com/MasterKale/SimpleWebAuthn/tree/master/packages/typescript-types#readme",
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

Deno.copyFileSync('README.md', `${outDir}/README.md`);
