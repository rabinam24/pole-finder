import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
<<<<<<< HEAD
import path from "path";
=======
import mkcert from "vite-plugin-mkcert";
import fs from "fs";
import path from "path";

const certPath = path.resolve(__dirname, "./certs");
const keyPath = path.resolve(certPath, "server.key");
const certFile = path.resolve(certPath, "server.cert");

// Check environment variable or fall back to default HTTPS setting
const useHttps = process.env.VITE_USE_HTTPS === 'true';

const httpsConfig = useHttps && fs.existsSync(keyPath) && fs.existsSync(certFile)
    ? {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certFile),
      }
    : false;
>>>>>>> origin/main

export default defineConfig({
  plugins: [
    react(),
<<<<<<< HEAD
=======
    mkcert(), // Use mkcert to handle SSL certificates
>>>>>>> origin/main
    VitePWA({
      registerType: "autoUpdate",
      manifest: {
        name: "Location Tracker",
        short_name: "Location Tracker",
        start_url: "/",
        display: "standalone",
        background_color: "#ffffff",
        theme_color: "#000000",
        description: "An application to track locations",
        icons: [
          {
            src: "/download.png",
            sizes: "192x192",
            type: "image/png",
          },
          {
            src: "/vite.svg",
            sizes: "any",
            type: "image/svg+xml",
          },
        ],
      },
      workbox: {
        runtimeCaching: [
          {
            urlPattern: ({ request }) => request.destination === "image",
            handler: "CacheFirst",
            options: {
              cacheName: "images",
              expiration: {
                maxEntries: 10,
                maxAgeSeconds: 60 * 60 * 24 * 30, // 30 days
              },
            },
          },
        ],
      },
    }),
  ],
  build: {
    rollupOptions: {
<<<<<<< HEAD
      external: [], // Ensure this list is correct
    },
    chunkSizeWarningLimit: 1000,
  },
  server: {
    https: false, // Set to false to use HTTP
    host: "0.0.0.0",
    port: 5173,
    proxy: {
      '/oauth/token': {
        target: 'http://oauth-staging.wlink.com.np',
=======
      external: ["react-oauth/google", "react-oauth/github"],
    },
    chunkSizeWarningLimit: 1000, // Adjust if you are getting chunk size warnings
  },
  server: {
    https: httpsConfig,
    host: "pole-finder.wlink.com.np",
    port: 5173,
    proxy: {
      '/oauth/token': {
        target: 'https://oauth-staging.wlink.com.np',
>>>>>>> origin/main
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/oauth\/token/, '/oauth/token'),
        secure: false,
      },
    },
<<<<<<< HEAD
=======
    middlewares: [
      (req, res, next) => {
        if (req.url.endsWith("sw.js")) {
          res.setHeader("Content-Type", "application/javascript");
        }
        next();
      },
    ],
>>>>>>> origin/main
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
