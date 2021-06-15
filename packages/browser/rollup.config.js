import typescript from '@rollup/plugin-typescript';
import nodeResolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';

/**
 * Rollup plugin to clean `tslib` comment in `UMD` bundle targeting `ES5`
 */
const cleanTslibCommentInUMDBundleTargetingES5 = () => {
  return {
    name: 'cleanTslibCommentInUMDBundleTargetingES5',
    renderChunk: async code => {
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

const swanVersionInjector = versionInjector({
  injectInComments: {
    fileRegexp: /\.(js)$/,
    // [@simplewebauthn/browser]  Version: 2.1.0 - Saturday, February 6th, 2021, 4:10:31 PM
    tag: '[@simplewebauthn/browser]  Version: {version} - {date}',
    dateFormat: 'dddd, mmmm dS, yyyy, h:MM:ss TT',
  },
});

/**
 * Rollup configuration to generate the following:
 * - ES2018 bundle
 * - ES5 bundle
 * - Type declarations
 */
export default [
  {
    input: 'src/index.ts',
    output: [
      {
        dir: 'dist',
        format: 'esm',
        entryFileNames: 'es2018/[name].mjs',
        preferConst: true,
      },
      {
        dir: 'dist',
        format: 'umd',
        name: 'SimpleWebAuthnBrowser',
        entryFileNames: 'es2018/[name].umd.min.js',
        plugins: [terser()],
      },
    ],
    plugins: [typescript({ tsconfig: './tsconfig.json' }), nodeResolve(), swanVersionInjector],
  },
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist',
      format: 'cjs',
      entryFileNames: 'es5/[name].js',
      exports: 'auto',
    },
    plugins: [typescript({ tsconfig: './tsconfig.es5.json' }), nodeResolve(), swanVersionInjector],
    external: ['tslib'],
  },
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist',
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      entryFileNames: 'es5/[name].umd.min.js',
      plugins: [terser(), cleanTslibCommentInUMDBundleTargetingES5()],
    },
    plugins: [typescript({ tsconfig: './tsconfig.es5.json' }), nodeResolve(), swanVersionInjector],
  },
];
