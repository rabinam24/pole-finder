import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";

import path from "path";


export default defineConfig({
  plugins: [
    react(),


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

        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/oauth\/token/, '/oauth/token'),
        secure: false,
      },
    },

    middlewares: [
      (req, res, next) => {
        if (req.url.endsWith("sw.js")) {
          res.setHeader("Content-Type", "application/javascript");
        }
        next();
      },
    ],

  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
  },
});
