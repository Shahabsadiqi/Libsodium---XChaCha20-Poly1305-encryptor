import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: './',  // For relative paths
  build: {
    target: 'es2020'  // Web Crypto support
  }
})
