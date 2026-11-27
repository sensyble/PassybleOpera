#!/usr/bin/env node
// Fails if any tracked text file contains an em dash (U+2014), literally or in an escaped form.
// The patterns are assembled from pieces so this file does not match its own check.
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const bs = String.fromCharCode(92);
const patterns = [
  String.fromCharCode(0x2014),
  bs + "u2014",
  bs + "u{2014}",
  "&" + "mdash;",
  "&#" + "8212;",
  "&#x" + "2014;",
];

const args = ["grep", "-I", "-n", "-i", "-F"];
for (const p of patterns) args.push("-e", p);

const r = spawnSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
if (r.error) {
  console.error(`check-no-emdash: could not run git: ${r.error.message}`);
  process.exit(2);
}
if (r.status === 0) {
  process.stdout.write(r.stdout);
  console.error("\ncheck-no-emdash: em dashes found (listed above). Rewrite them with a period, comma, colon or parentheses.");
  process.exit(1);
}
if (r.status !== 1) {
  console.error(`check-no-emdash: git grep failed (${r.status}): ${r.stderr}`);
  process.exit(2);
}
console.log("check-no-emdash: ok (no em dashes in tracked files)");
