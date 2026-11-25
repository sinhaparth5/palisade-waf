import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { codecovVitePlugin } from "@codecov/vite-plugin";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import { goTemplate, precompress, sonnerNoInlineStyle, unbrand, devPalisade } from "./build/palisade.ts";

// Built for the Go server (internal/ui/app.go), which renders dist/index.html
// as an html/template and serves dist/assets/*. See build/palisade.ts.
// `--mode login` builds the public sign-in page (login.html) on its own into
// dist/login, so nothing of the app is served before a session exists.
export default defineConfig(({ command, mode }) => ({
  // Build: relative, so CSS fonts and lazy chunks resolve next to their file
  // wherever the admin path puts them. Dev: under the default admin path.
  base: command === "build" ? "./" : "/admin/",
  plugins: [
    // Not under Vitest: routeTree.gen.ts is committed, and the plugin's code
    // splitting and HMR code add branches to route files no test can reach.
    !process.env.VITEST && tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
    sonnerNoInlineStyle(),
    unbrand({ partial: mode === "login" }),
    goTemplate(),
    precompress(),
    devPalisade(process.env.PALISADE_URL ?? "http://127.0.0.1:8080"),
    // Bundle size per build to Codecov, only where CI passes the token (empty
    // on fork PRs). A failed upload is logged, not a failed build. Last, so it
    // sees the files as written.
    codecovVitePlugin({
      enableBundleAnalysis: !!process.env.CODECOV_TOKEN,
      bundleName: mode === "login" ? "admin-login" : "admin-app",
      uploadToken: process.env.CODECOV_TOKEN,
      telemetry: false,
    }),
  ],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: mode === "login" ? "../static/app/dist/login" : "../static/app/dist",
    emptyOutDir: true,
    sourcemap: false,
    // Third-party licence notices, next to THIRD_PARTY_NOTICES.md for the Go side
    // (the login bundle's libraries are a subset of the app's).
    license: mode !== "login" && { fileName: "licenses.md" },
    rolldownOptions: {
      input: fileURLToPath(new URL(mode === "login" ? "./login.html" : "./index.html", import.meta.url)),
      output: {
        // Hash-only names: a file name shouldn't announce the libraries inside.
        entryFileNames: "assets/[hash].js",
        chunkFileNames: "assets/[hash].js",
        assetFileNames: "assets/[hash][extname]",
        // Libraries change less often than our code, so a release only
        // re-downloads what changed. Heavy page-only libraries (recharts,
        // tanstack table) stay in the lazy route chunks that import them.
        codeSplitting: {
          groups: [
            { name: "react", test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/, priority: 3 },
            { name: "tanstack", test: /node_modules[\\/]@tanstack[\\/](react-router|router-core|react-query|query-core|history|store|react-store)[\\/]/, priority: 2 },
            { name: "ui", test: /node_modules[\\/](radix-ui|@radix-ui|sonner|class-variance-authority|clsx|tailwind-merge|get-nonce)[\\/]/, priority: 1 },
          ],
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}", "build/**/*.test.ts"],
    // Every test starts clean: mocks reset, vi.stubGlobal (fetch, location) undone.
    restoreMocks: true,
    unstubGlobals: true,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/**/*.test.{ts,tsx}", "src/test/**", "src/routeTree.gen.ts", "src/components/ui/**", "src/main.tsx"],
      reporter: ["text-summary", "lcov"],
    },
    // Run sonner through the plugins above, so the CSP test sees the build's code.
    server: { deps: { inline: ["sonner"] } },
  },
}));
