import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";

export default defineConfig({
  // Self-contained: no external CDNs. WASM is fetched from the same origin.
  base: "./",

  plugins: [
    VitePWA({
      registerType: "autoUpdate",
      includeAssets: ["icon-192.png", "icon-512.png", "icon.svg"],
      manifest: {
        name: "ubi2 Light Node",
        short_name: "ubi2 Node",
        description:
          "A node in your browser — syncs the ubi2 chain, re-executes every block in WASM, and verifies state trustlessly.",
        theme_color: "#07080c",
        background_color: "#07080c",
        display: "standalone",
        orientation: "portrait-primary",
        start_url: "./",
        icons: [
          {
            src: "icon-192.png",
            sizes: "192x192",
            type: "image/png",
            purpose: "any maskable",
          },
          {
            src: "icon-512.png",
            sizes: "512x512",
            type: "image/png",
            purpose: "any maskable",
          },
          {
            src: "icon.svg",
            sizes: "any",
            type: "image/svg+xml",
          },
        ],
      },
      workbox: {
        // Cache WASM + JS bundles for offline last-verified read (spec §3.3, AC-LC7).
        globPatterns: ["**/*.{js,css,html,wasm,svg,png,ico}"],
        runtimeCaching: [
          {
            urlPattern: /\.wasm$/,
            handler: "CacheFirst",
            options: {
              cacheName: "wasm-cache",
              expiration: { maxEntries: 5, maxAgeSeconds: 7 * 24 * 60 * 60 },
            },
          },
        ],
      },
    }),
  ],

  build: {
    target: "es2022",
    // Inline small assets; keep WASM external for cache efficiency.
    assetsInlineLimit: 4096,
    rollupOptions: {
      output: {
        // Stable chunk names for service-worker caching.
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash][extname]",
      },
    },
  },

  // Allow WASM imports.
  optimizeDeps: {
    exclude: ["@ubi2/light-client"],
  },

  server: {
    port: 3001,
    cors: true,
  },
});
