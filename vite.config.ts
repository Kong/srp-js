import { resolve } from "path";
import { nodePolyfills } from "vite-plugin-node-polyfills";
import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, "src/index.ts"),
      name: "insomnia-srp-client",
      // the proper extensions will be added
      fileName: "index"
    },
    rollupOptions: {
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      output: {
        // Provide global variables to use in the UMD build
        // for externalized deps
      }
    }
  },
  plugins: [nodePolyfills()]
});
