import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In Docker, API_HOST is set to the compose service name ("ids").
// Locally it falls back to "localhost".
const host = process.env.API_HOST ?? 'localhost'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/ws': {
        target: `ws://${host}:8000`,
        ws: true,
      },
      '/api': {
        target: `http://${host}:8000`,
        changeOrigin: true,
      },
      '/health': {
        target: `http://${host}:8000`,
        changeOrigin: true,
      },
    },
  },
})
