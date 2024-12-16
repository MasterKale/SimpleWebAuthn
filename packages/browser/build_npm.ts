import { build, emptyDir } from '@deno/dnt';
import { type OutputOptions, rollup, type RollupOptions } from 'rollup';
import terser from '@rollup/plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import { getBabelOutputPlugin } from '@rollup/plugin-babel';
import replace from '@rollup/plugin-replace';

import denoJSON from './deno.json' with { type: 'json' };

const outDir = './npm';

/**
 * Generate ESM and CJS builds using Deno to Node Transform (dnt)
 */
async function buildESMAndCJS() {
  await emptyDir(outDir);

  await build({
    entryPoints: ['./src/index.ts'],
    outDir,
    importMap: './deno.json',
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
      unpkg: 'dist/bundle/index.umd.min.js',
      dependencies: {},
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
 * Generate UMD bundles using Rollup and Babel
 */
async function buildUMDES5() {
  console.log('Building UMD (ES5) bundle...');

  const rollupOptionsES5: RollupOptions = {
    // Process the ESM .js files generated by dnt
    input: `${outDir}/esm/index.js`,
    output: {
      dir: `${outDir}/dist`,
      // Output to ESM so Babel can take care of UMD generation
      format: 'esm',
      entryFileNames: 'bundle/[name].es5.umd.min.js',
      plugins: [
        /**
         * Add polyfills/etc... as needed to target the lowest common denominator browser
         */
        getBabelOutputPlugin({
          moduleId: 'SimpleWebAuthnBrowser',
          presets: [
            [
              '@babel/preset-env',
              {
                modules: 'umd',
                /**
                 * Targeting IE 10 makes the bundle kinda big but at least with this
                 * `browserSupportsWebAuthn()` can return false
                 */
                targets: { ie: 10 },
              },
            ],
          ],
        }),
        cleanCopyrightCommentInUMDBundleTargetingES5(),
        // @ts-ignore: Rollup plugins are callable
        terser(),
        swanVersionInjector(),
      ],
    },
    plugins: [
      // @ts-ignore: Rollup plugins are callable
      replace({
        preventAssignment: true,
        values: {
          // Replace Deno testing-mandated use of `globalThis` with more natural `window`
          'globalThis': 'window',
        },
        // Replace all instances of the strings specified above
        delimiters: ['', ''],
      }),
      // @ts-ignore: Rollup plugins are callable
      nodeResolve(),
    ],
  };

  try {
    // Process inputs
    // Generate a bundle
    const bundle = await rollup(rollupOptionsES5);

    console.log('Writing bundle...');
    // Write the bundle to file
    await bundle.write(rollupOptionsES5.output as OutputOptions);

    // Close the bundle
    await bundle.close();
  } catch (error) {
    throw new Error('Failed to generate Rollup bundle', { cause: error });
  }

  console.log('Complete!');
}

async function buildUMDES2021() {
  console.log('Building UMD (ES2021) bundle...');

  const rollupOptionsES2021: RollupOptions = {
    // Process the ESM .js files generated by dnt
    input: `${outDir}/esm/index.js`,
    output: {
      dir: `${outDir}/dist`,
      // Output to ESM so Babel can take care of UMD generation
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      entryFileNames: 'bundle/[name].umd.min.js',
      plugins: [
        // @ts-ignore: Rollup plugins are callable
        terser(),
        swanVersionInjector(),
      ],
    },
    plugins: [
      // @ts-ignore: Rollup plugins are callable
      nodeResolve(),
    ],
  };

  try {
    // Process inputs
    // Generate a bundle
    const bundle = await rollup(rollupOptionsES2021);

    console.log('Writing bundle...');
    // Write the bundle to file
    await bundle.write(rollupOptionsES2021.output as OutputOptions);

    // Close the bundle
    await bundle.close();
  } catch (error) {
    throw new Error('Failed to generate Rollup bundle', { cause: error });
  }

  console.log('Complete!');
}

/**
 * Generate the builds
 */
await buildESMAndCJS();
await buildUMDES5();
await buildUMDES2021();

/**
 * Rollup plugin to remove injected copyright notices
 */
function cleanCopyrightCommentInUMDBundleTargetingES5() {
  return {
    name: 'cleanCopyrightCommentInUMDBundleTargetingES5',
    renderChunk: (code: string) => {
      const comment =
        `/*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/facebook/regenerator/blob/main/LICENSE */`;
      return code.indexOf(comment) > -1 ? code.replace(comment, '') : null;
    },
  };
}

/**
 * Add the package name and version to the top of the bundle
 */
function swanVersionInjector() {
  // @ts-ignore: Rollup plugins are callable
  return versionInjector({
    packageJson: `${outDir}/package.json`,
    injectInComments: {
      fileRegexp: /\.(js)$/,
      // [@simplewebauthn/browser@2.1.0]
      tag: '[@simplewebauthn/browser@{version}]',
    },
  });
}
