import { build, emptyDir } from '@deno/dnt';
import { type InputOption, type OutputOptions, rollup, type RollupBuild } from 'rollup';
import terser from '@rollup/plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';

const outDir = './npm';

const denoJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('./deno.jsonc'),
);
const typesDenoJSON: { version: string } = JSON.parse(
  Deno.readTextFileSync('../types/deno.jsonc'),
);

/**
 * ESM and CJS builds
 */
async function buildESMAndCJS() {
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
        'umd',
      ],
      dependencies: {
        // Deno workspaces maps this identifier locally, make sure it's defined in the NPM package
        '@simplewebauthn/types': `^${typesDenoJSON.version}`,
      },
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
}

/**
 * UMD build
 */
async function buildUMD() {
  // Rollup plugin to clean `tslib` comment in `UMD` bundle targeting `ES5`
  const cleanTslibCommentInUMDBundleTargetingES5 = () => {
    return {
      name: 'cleanTslibCommentInUMDBundleTargetingES5',
      renderChunk: async (code: string) => {
        const comment = `
/*! *****************************************************************************
    Copyright (c) Microsoft Corporation.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose with or without fee is hereby granted.

    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
    REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
    AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
    INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
    LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
    OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
    PERFORMANCE OF THIS SOFTWARE.
    ***************************************************************************** */`;
        return code.indexOf(comment) > -1 ? code.replace(comment, '') : null;
      },
    };
  };

  // @ts-ignore: yes, `versionInjector()` is callable
  const swanVersionInjector = versionInjector({
    packageJson: `${outDir}/package.json`,
    injectInComments: {
      fileRegexp: /\.(js)$/,
      // [@simplewebauthn/browser@2.1.0]
      tag: '[@simplewebauthn/browser@{version}]',
    },
  });

  const rollupInputOptions: InputOption = `${outDir}/esm/index.js`;
  const rollupOutputOptions: OutputOptions = {
    dir: `${outDir}`,
    format: 'umd',
    name: 'SimpleWebAuthnBrowser',
    entryFileNames: 'bundle/[name].es5.umd.min.js',
    plugins: [
      // TODO: Figure out how to get this back up and running
      // typescript({ tsconfig: './tsconfig.es5.json' }),
      // @ts-ignore: yes, `terser()` is callable
      terser(),
      // TODO: Figure out how to get this back up and running
      // cleanTslibCommentInUMDBundleTargetingES5(),
      swanVersionInjector,
    ],
  };

  let bundle: RollupBuild;
  try {
    // Process inputs
    bundle = await rollup({ input: rollupInputOptions });

    // an array of file names this bundle depends on
    // console.log(bundle.watchFiles);

    // Write the bundle to file
    await bundle.write(rollupOutputOptions);

    // Close the bundle
    await bundle.close();
  } catch (error) {
    throw new Error('Failed to generate Rollup bundle', { cause: error });
  }
}

await buildESMAndCJS();
await buildUMD();
