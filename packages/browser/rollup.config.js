import commonjs from '@rollup/plugin-commonjs';
import resolve from '@rollup/plugin-node-resolve';
import typescript from '@rollup/plugin-typescript';
import { terser } from 'rollup-plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';

export default {
  input: 'src/index.ts',
  // input: 'dist/es5/index.js',
  output: [
    // {
    //   file: 'dist/bundles/bundle.esm.js',
    //   format: 'esm',
    //   sourcemap: true,
    // },
    // {
    //   file: 'dist/bundles/bundle.esm.min.js',
    //   format: 'esm',
    //   sourcemap: true,
    //   plugins: [terser()],
    // },
    // {
    //   file: 'dist/bundles/bundle.umd.js',
    //   format: 'umd',
    //   name: 'SimpleWebAuthnBrowser',
    //   sourcemap: true,
    // },
    {
      file: 'dist/bundles/bundle.umd.min.js',
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      plugins: [terser()],
      sourcemap: true,
    },
  ],
  plugins: [
    typescript({ tsconfig: './tsconfig.es5.json' }),
    commonjs({ extensions: ['.ts'] }),
    versionInjector({
      injectInComments: {
        fileRegexp: /\.(js)$/,
        // [@simplewebauthn/browser]  Version: 2.1.0 - Saturday, February 6th, 2021, 4:10:31 PM
        tag: '[@simplewebauthn/browser]  Version: {version} - {date}',
        dateFormat: 'dddd, mmmm dS, yyyy, h:MM:ss TT',
      },
    }),
  ],
};
