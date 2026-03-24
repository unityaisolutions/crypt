import { build } from "bun";

async function runBuild() {
  console.log("Building browser and ESM bundles...");

  // Build minified version for standard browser <script> tags
  await build({
    entrypoints: ["./src/index.ts"],
    outdir: "./dist",
    target: "browser",
    minify: true,
    naming: "index.min.js",
  });

  // Build standard ESM module
  await build({
    entrypoints: ["./src/index.ts"],
    outdir: "./dist",
    target: "browser",
    format: "esm",
    naming: "index.mjs",
  });

  // CommonJS
  await build({
    entrypoints: ["./src/index.ts"],
    outdir: "./dist",
    target: "browser",
    naming: "index.js",
  });

  console.log("Build complete!");
}

runBuild();