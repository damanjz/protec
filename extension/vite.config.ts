import { defineConfig } from "vite";
export default defineConfig({
  test: { environment: "jsdom" },
  build: {
    rollupOptions: {
      input: {
        background: "src/background.ts",
        content: "src/content.ts",
        popup: "src/popup.ts",
      },
      output: { entryFileNames: "[name].js", format: "es" },
    },
    outDir: "dist",
  },
});
