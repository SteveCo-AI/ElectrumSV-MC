export default {
  root: 'tools/wry-proof',
  base: './',
  build: { outDir: '/tmp/wallet-wry-proof-assets', emptyOutDir: true, rollupOptions: { output: { entryFileNames: 'gate.js' } } },
};
