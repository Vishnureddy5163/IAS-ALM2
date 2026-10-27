import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/p1': {
        target: 'http://localhost:5001',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/p1/, '')
      },
      '/p2': {
        target: 'http://localhost:5002',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/p2/, '')
      },
      '/p3': {
        target: 'http://localhost:5003',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/p3/, '')
      }
    }
  }
})
