import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

// Dev server proxies /api and /enroll to the local gateway so the SPA
// can make same-origin requests without hand-rolling CORS. In production
// the SPA is served by a CDN and the gateway sits behind its own
// domain; config.cors.allowed_origins on the gateway governs access.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_TARGET ?? 'http://localhost:8443';

  return {
    plugins: [react()],
    server: {
      port: 5173,
      proxy: {
        '/api': { target: apiTarget, changeOrigin: true, secure: false },
        '/enroll': { target: apiTarget, changeOrigin: true, secure: false },
      },
    },
    build: { outDir: 'dist', sourcemap: true },
  };
});
