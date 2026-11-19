import { resolve } from 'node:path';
export default {
  root: 'tools/wry-payment', base: './',
  resolve: { alias: [
    { find: /^react$/, replacement: resolve('gui/node_modules/react') },
    { find: /^react-dom\//, replacement: resolve('gui/node_modules/react-dom') + '/' },
    { find: /^@tauri-apps\/api\//, replacement: resolve('gui/node_modules/@tauri-apps/api') + '/' },
  ] },
  build: { outDir: '/tmp/wallet-wry-payment-assets', emptyOutDir: true, rollupOptions: { output: { entryFileNames: 'gate.js', assetFileNames: 'gate.[ext]', inlineDynamicImports: true } } },
};
