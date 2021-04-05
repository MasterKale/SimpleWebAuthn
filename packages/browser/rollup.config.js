import typescript from '@rollup/plugin-typescript';
import commonjs from '@rollup/plugin-commonjs';
import nodeResolve from '@rollup/plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
import versionInjector from 'rollup-plugin-version-injector';

export default {
  input: 'src/index.ts',
  output: [
    {
      file: 'dist/bundles/bundle.umd.min.js',
      format: 'umd',
      name: 'SimpleWebAuthnBrowser',
      plugins: [terser()],
    },
  ],
  plugins: [
    typescript({ tsconfig: './tsconfig.es5.json' }),
    commonjs({ extensions: ['.js', '.ts'] }),
    nodeResolve({ mainFields: ['jsnext:main', 'module', 'main'] }),
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
