import { resolve } from 'path'
import { defineConfig } from 'vite';
import { viteStaticCopy } from 'vite-plugin-static-copy'

export default defineConfig({
  base: '',
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
  plugins: [
    viteStaticCopy({
      targets: [
        {
          src: resolve(__dirname, 'node_modules','swagger-ui-dist','swagger-ui-bundle.js'),
          dest: resolve(__dirname,'static','assets')
        },
        {
          src: resolve(__dirname, 'node_modules','swagger-ui-dist','swagger-ui.css'),
          dest: resolve(__dirname,'static','assets')
        },
        {
          src: resolve(__dirname, 'node_modules','redoc','bundles','redoc.standalone.js'),
          dest: resolve(__dirname,'static','assets')
        }
      ]
    })
  ]
})
