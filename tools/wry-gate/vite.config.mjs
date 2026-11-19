export default {
  root: 'tools/wry-gate',
  base: './',
  build: { outDir: '/tmp/wallet-wry-gate-assets', emptyOutDir: true, rollupOptions: { output: { entryFileNames: 'gate.js' } } },
};
