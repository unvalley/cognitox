import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  base: '/',
  plugins: [preact(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/oauth2': 'http://localhost:9229',
      '/.well-known': 'http://localhost:9229',
    }
  }
})
