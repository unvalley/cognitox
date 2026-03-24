import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import { resolve } from 'path'

export default defineConfig({
  base: './',
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      // Proxy API requests to Rust server
      '/oauth2': 'http://localhost:9229',
      '/.well-known': 'http://localhost:9229',
    }
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        admin: resolve(__dirname, 'admin.html'),
      },
    },
  }
})
