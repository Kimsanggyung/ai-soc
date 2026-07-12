import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss()
  ],
  base: '/',
  // 💡 리액트를 3000번 포트에서 독립 가동하고 8000번 파이썬 백엔드와 중계 통로를 개설합니다.
  server: {
    port: 3000, 
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000', // 💡 main.py가 띄운 8000번 포트로 정밀 결속
        changeOrigin: true,
      }
    }
  },
  build: {
    outDir: resolve(__dirname, '../fastapi/static'),
    emptyOutDir: false,
    rollupOptions: {
      input: {
        react_dashboard: resolve(__dirname, 'index.html'),
      },
      output: {
        entryFileNames: 'assets/[name].js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name].[ext]',
      }
    }
  }
})