import typescript from '@rollup/plugin-typescript';
import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
// import versionInjector from 'rollup-plugin-version-injector';

/**
 * Rollup plugin to clean `tslib` comment in `UMD` bundle targeting `ES5`
 */
const cleanTslibCommentInUMDBundleTargetingES5 = () => {
  return {
    name: 'cleanTslibCommentInUMDBundleTargetingES5',
    renderChunk: async code => {
      const comment = `
/*! *****************************************************************************
\tCopyright (c) Microsoft Corporation.

\tPermission to use, copy, modify, and/or distribute this software for any
\tpurpose with or without fee is hereby granted.

\tTHE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
\tREGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
\tAND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
\tINDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
\tLOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
\tOTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
\tPERFORMANCE OF THIS SOFTWARE.
\t***************************************************************************** */
`;
      return code.indexOf(comment) > -1 ? code.replace(comment, '') : null;
    },
  };
};

/**
 * Re-enable version injection when this gets resolved:
 *
 * https://github.com/djhouseknecht/rollup-plugin-version-injector/issues/22
 *
 * To avoid a repeat of the first half of this:
 *
 * https://github.com/MasterKale/SimpleWebAuthn/issues/56
 */
// const swanVersionInjector = versionInjector({
//   injectInComments: {
//     fileRegexp: /\.(js)$/,
//     // [@simplewebauthn/browser]  Version: 2.1.0 - Saturday, February 6th, 2021, 4:10:31 PM
//     tag: '[@simplewebauthn/browser]  Version: {version} - {date}',
//     dateFormat: 'dddd, mmmm dS, yyyy, h:MM:ss TT',
//   },
// });

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
        entryFileNames: 'es2018/[name].js',
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
    plugins: [
      typescript({ tsconfig: './tsconfig.json' }),
      nodeResolve(),
      // swanVersionInjector,
    ],
  },
  {
    input: 'src/index.ts',
    output: {
      dir: 'dist',
      format: 'cjs',
      entryFileNames: 'es5/[name].js',
      exports: 'auto',
    },
    plugins: [
      typescript({ tsconfig: './tsconfig.es5.json' }),
      commonjs({ extensions: ['.ts'] }),
      nodeResolve(),
      // swanVersionInjector,
    ],
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
    plugins: [
      typescript({ tsconfig: './tsconfig.es5.json' }),
      commonjs({ extensions: ['.ts'] }),
      nodeResolve(),
      // swanVersionInjector,
    ],
  },
];
