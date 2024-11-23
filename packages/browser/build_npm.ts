import { build, emptyDir } from '@deno/dnt';
import { rollup, type RollupOptions, type OutputOptions } from 'rollup';
import terser from '@rollup/plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';
import nodeResolve from '@rollup/plugin-node-resolve';

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
      target: 'ES2021',
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

  const rollupOptions: RollupOptions = {
    input: `${outDir}/esm/index.js`,
    output: {
      dir: `${outDir}`,
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      entryFileNames: 'bundle/[name].es5.umd.min.js',
      plugins: [
        // @ts-ignore: `terser()` is callable
        terser(),
        cleanTslibCommentInUMDBundleTargetingES5(),
      ],
    },
    plugins: [
      // TODO: Figure out how to get this back up and running
      // typescript({ tsconfig: './tsconfig.es5.json' }),
      // @ts-ignore: `nodeResolve()` is callable
      nodeResolve(),
      swanVersionInjector,
    ],
  };

  try {
    // Process inputs
    const bundle = await rollup(rollupOptions);

    // an array of file names this bundle depends on
    // console.log(bundle.watchFiles);

    // Write the bundle to file
    await bundle.write(rollupOptions.output as OutputOptions);

    // Close the bundle
    await bundle.close();
  } catch (error) {
    throw new Error('Failed to generate Rollup bundle', { cause: error });
  }
}

await buildESMAndCJS();
await buildUMD();
