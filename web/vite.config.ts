import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { tanstackRouter } from "@tanstack/router-plugin/vite";
import { goTemplate, precompress, sonnerNoInlineStyle, devPalisade } from "./build/palisade.ts";

// Built for the Go server (internal/ui/app.go), which renders dist/index.html
// as an html/template and serves dist/assets/*. See build/palisade.ts.
export default defineConfig(({ command }) => ({
  // Build: relative, so CSS fonts and lazy chunks resolve next to their file
  // wherever the admin path puts them. Dev: under the default admin path.
  base: command === "build" ? "./" : "/admin/app/",
  plugins: [
    tanstackRouter({ target: "react", autoCodeSplitting: true }),
    react(),
    tailwindcss(),
    sonnerNoInlineStyle(),
    goTemplate(),
    precompress(),
    devPalisade(process.env.PALISADE_URL ?? "http://127.0.0.1:8080"),
  ],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: {
    outDir: "../static/app/dist",
    emptyOutDir: true,
    sourcemap: false,
    // Third-party licence notices, next to THIRD_PARTY_NOTICES.md for the Go side.
    license: { fileName: "licenses.md" },
    rolldownOptions: {
      output: {
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
    include: ["src/**/*.test.{ts,tsx}"],
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
