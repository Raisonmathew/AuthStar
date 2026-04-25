import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'
import tailwindcss from 'tailwindcss'
import autoprefixer from 'autoprefixer'

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    css: {
        postcss: {
            plugins: [
                tailwindcss,
                autoprefixer,
            ],
        },
    },
    server: {
        port: 5173,
        proxy: {
            '/api': {
                target: 'http://localhost:3000',
                changeOrigin: true,
            },
            '/oauth': {
                target: 'http://localhost:3000',
                changeOrigin: true,
                // `/oauth/consent` is a frontend SPA route (consent UI page).
                // All other `/oauth/*` paths (authorize, token, introspect, revoke)
                // are backend OAuth 2.0 endpoints. Bypass forwards `/oauth/consent`
                // back to Vite so the SPA fallback serves index.html.
                bypass: (req) => {
                    if (req.url && req.url.startsWith('/oauth/consent')) {
                        return req.url;
                    }
                    return null;
                },
            },
            '/.well-known': {
                target: 'http://localhost:3000',
                changeOrigin: true,
            },
        },
    },
})


