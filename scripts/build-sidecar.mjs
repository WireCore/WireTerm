// Builds the Go sidecar for the machine this runs on, or for another target:
//
//   npm run build:sidecar                                # this machine
//   npm run build:sidecar -- x86_64-apple-darwin         # an Intel Mac, built on Apple Silicon
//
// Tauri expects the binary at binaries/op-sidecar-<target-triple>[.exe], where
// the triple is the one rustc reports for the host (or the one passed to
// `tauri build --target`). Asking rustc keeps this in step with what Tauri
// looks for, on Windows, Linux and macOS alike.
//
// On Linux and macOS the 1Password SDK needs CGO, so gcc or clang must be
// installed. Cross-building with CGO is only set up for macOS, where clang
// builds for both architectures; elsewhere build on the target's own machine.
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

const host = execFileSync("rustc", ["-vV"], { encoding: "utf8" }).match(/^host: (.+)$/m)?.[1];
if (!host) throw new Error("could not read the host target triple from `rustc -vV`");
const target = process.argv[2] ?? host;

const GOARCH = { x86_64: "amd64", aarch64: "arm64" };
const arch = target.split("-")[0];
const goos = target.includes("windows") ? "windows" : target.includes("apple") ? "darwin" : "linux";
if (!GOARCH[arch]) throw new Error(`no Go architecture known for ${target}`);

const env = { ...process.env };
if (target !== host) {
  env.GOOS = goos;
  env.GOARCH = GOARCH[arch];
  if (goos === "darwin") {
    env.CGO_ENABLED = "1";
    env.CC = `clang -arch ${arch === "aarch64" ? "arm64" : "x86_64"}`;
  }
}

const ext = goos === "windows" ? ".exe" : "";
const out = join(root, "src-tauri", "binaries", `op-sidecar-${target}${ext}`);
mkdirSync(dirname(out), { recursive: true });

execFileSync("go", ["build", "-ldflags=-s -w", "-o", out, "."], {
  cwd: join(root, "sidecar"),
  env,
  stdio: "inherit",
});
console.log(`built ${out}`);
