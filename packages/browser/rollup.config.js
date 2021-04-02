import babel from '@rollup/plugin-babel';
import resolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';

const extensions = ['.ts'];

export default {
  input: 'src/index.ts',
  output: [
    {
      file: 'dist/bundles/bundle.esm.js',
      format: 'esm',
      sourcemap: true,
    },
    {
      file: 'dist/bundles/bundle.esm.min.js',
      format: 'esm',
      plugins: [terser()],
      sourcemap: true,
    },
    {
      file: 'dist/bundles/bundle.umd.js',
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      sourcemap: true,
    },
    {
      file: 'dist/bundles/bundle.umd.min.js',
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      plugins: [terser()],
      sourcemap: true,
    },
  ],
  plugins: [
    resolve({ extensions }),
    babel({
      babelHelpers: 'bundled',
      include: ['src/**/*.ts'],
      extensions,
      exclude: './node_modules/**',
    }),
    versionInjector({
      injectInComments: {
        fileRegexp: /\.(js)$/,
        // [@simplewebauthn/browser]  Version: 2.1.0 - Saturday, February 6th, 2021, 4:10:31 PM
        tag: '/* [@simplewebauthn/browser]  Version: {version} - {date} */',
        dateFormat: 'dddd, mmmm dS, yyyy, h:MM:ss TT',
      },
    }),
  ],
};
