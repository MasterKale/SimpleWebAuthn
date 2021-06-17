import typescript from '@rollup/plugin-typescript';
import nodeResolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';

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
 * - Type declarations
 */
export default [
  {
    input: 'src/index.ts',
    output: [
      {
        dir: 'dist',
        format: 'esm',
        entryFileNames: 'bundle/[name].js',
        preferConst: true,
      },
      {
        dir: 'dist',
        format: 'umd',
        name: 'SimpleWebAuthnBrowser',
        entryFileNames: 'bundle/[name].umd.min.js',
        plugins: [terser()],
      },
    ],
    plugins: [typescript({ tsconfig: './tsconfig.json' }), nodeResolve(), swanVersionInjector],
  },
];
