import { resolve } from 'path'
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        layout: resolve(__dirname, 'resources', 'css', 'app.scss'),
        digid_mock: resolve(__dirname, 'resources', 'js', 'digid_mock.js'),
        submit: resolve(__dirname, 'resources', 'js', 'submit.js'),
      },
    },
    outDir: '',
    assetsDir: 'static/assets',
    manifest: 'static/assets/manifest.json',
    emptyOutDir: false,
  },
})