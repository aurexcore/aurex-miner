import fs from "node:fs";
import path from "node:path";
import esbuild from "esbuild";

const OUT_DIR = "dist";
const OUT_FILE = path.join(OUT_DIR, "miner.cjs");
const BIN_FILE = path.join(OUT_DIR, "aurex-miner");
fs.mkdirSync(OUT_DIR, { recursive: true });

await esbuild.build({
    entryPoints: ["miner.js"],
    outfile: OUT_FILE,
    bundle: true,
    platform: "node",
    format: "cjs",
    target: "node18",
    sourcemap: false,
    minify: true,
    external: ["os", "crypto", "worker_threads"],
    define: { "process.env.NODE_ENV": '"production"' },
});

const shebang = "#!/usr/bin/env node\n";
let code = fs.readFileSync(OUT_FILE, "utf8");

code = code.replace(/^#!.*\r?\n/gm, (m, offset) => (offset === 0 ? m : ""));

if (!code.startsWith(shebang)) {
    code = shebang + code.replace(/^\uFEFF/, "");
    fs.writeFileSync(OUT_FILE, code, "utf8");
}

fs.writeFileSync(
    BIN_FILE,
    `#!/usr/bin/env node
require("./miner.cjs");
`,
    "utf8"
);

try {
    fs.chmodSync(OUT_FILE, 0o755);
    fs.chmodSync(BIN_FILE, 0o755);
} catch { }

console.log("✅ Build OK");
console.log("   -", OUT_FILE);
console.log("   -", BIN_FILE);