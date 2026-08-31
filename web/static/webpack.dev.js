const path = require('path');
const webpack = require('webpack');
const { merge } = require('webpack-merge');

const common = require('./webpack.common.js');

module.exports = merge(common, {
  mode: 'development',
  module: {
    rules: [
      {
        test: /\.css$/i,
        use: ['style-loader', 'css-loader']
      },
    ]
  },
  output: {
    filename: 'js/[name].[contenthash].bundle.js',
    path: path.resolve(__dirname, 'dist'),
    clean: true
  },
  plugins: [
    new webpack.NormalModuleReplacementPlugin(
        /^@\/config\/secret-workflow-dispatch-app-private-key\.pem$/,
        path.resolve(__dirname, 'src/config/secret-workflow-dispatch-app-private-key.dev.pem')
    ),
    new webpack.NormalModuleReplacementPlugin(
        /^@\/config\/conf\.yaml$/,
        path.resolve(__dirname, 'src/config/conf.dev.yaml')
    ),
  ],
});

