import { fileURLToPath } from 'node:url';
import vue from '@vitejs/plugin-vue';
import { defineConfig } from 'vite';

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url));

// Build del webview: un solo main.js + main.css (y la fuente de Codicons) en dist/webview,
// con nombres fijos para que la extensión los referencie desde el HTML con CSP.
export default defineConfig({
  root: here('.'),
  base: './',
  plugins: [vue()],
  build: {
    outDir: here('../dist/webview'),
    emptyOutDir: true,
    target: 'es2022',
    cssCodeSplit: false,
    modulePreload: false,
    rollupOptions: {
      input: here('src/main.ts'),
      output: {
        entryFileNames: 'main.js',
        assetFileNames: (asset) => (asset.names?.[0]?.endsWith('.css') ? 'main.css' : '[name][extname]'),
      },
    },
  },
});
