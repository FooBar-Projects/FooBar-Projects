const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');

const baseCSS = path.resolve(__dirname, 'src/base.css');

entries = {
  'index': [
    baseCSS,
    path.resolve(__dirname, 'src/index.js'),
    path.resolve(__dirname, 'src/index.css')
  ]
};

htmlPlugins = [
  new HtmlWebpackPlugin({
    template: path.resolve(__dirname, `src/index.html`),
    filename: 'index.html',
    chunks: ['index']
  })
];

non_index_pages = [];
non_index_pages.forEach((page) => {
  entries[page] = [
    baseCSS,
    path.resolve(__dirname, `src/${page}/index.js`),
    path.resolve(__dirname, `src/${page}/index.css`)
  ];

  htmlPlugins.push(new HtmlWebpackPlugin({
    template: path.resolve(__dirname, `src/${page}/index.html`),
    filename: `${page}/index.html`,
    chunks: [page]
  }));
});

module.exports = {
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src/')
    }
  },
  entry: entries,
  plugins: [
    ...htmlPlugins
  ],
  module: {
    rules: [
      {
        test: /\.ya?ml$/i,
        use: ['yaml-loader']
      },
    ]
  }
};

