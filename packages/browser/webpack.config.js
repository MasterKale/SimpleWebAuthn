const path = require('path');
const WebpackAutoInject = require('webpack-auto-inject-version');

const outputPath = path.resolve(__dirname, 'dist');

module.exports = {
  entry: './src/index.ts',
  mode: 'production',
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /.ts$/,
        use: 'ts-loader',
        exclude: /node_modules/,
      },
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  output: {
    path: outputPath,
    filename: 'simplewebauthn-browser.min.js',
    library: 'SimpleWebAuthnBrowser',
    libraryTarget: 'umd',
    globalObject: 'this',
  },
  plugins: [
    new WebpackAutoInject({
      SHORT: '@webauthentine/browser',
      PACKAGE_JSON_INDENT: 2,
      components: {
        AutoIncreaseVersion: false,
      },
      componentsOptions: {
        InjectAsComment: {
          tag: 'Version: {version} - {date}',
          multiLineCommentType: true,
        },
      },
    }),
  ],
};
