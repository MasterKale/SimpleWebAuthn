const path = require('path');

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
      }
    ],
  },
  resolve: {
    extensions: ['.ts', '.js'],
  },
  output: {
    path: outputPath,
    filename: 'webauthntine-browser.min.js',
    library: 'WebAuthntineBrowser',
    libraryTarget: 'umd',
  },
};
