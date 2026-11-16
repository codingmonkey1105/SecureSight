// Usage: node eval/export_features.js eval/urls.csv eval/features.csv
// Uses the SAME feature extractor as the extension, so training and runtime can never drift apart.
const fs = require("fs");
const R = require("../risk-engine.js");
const { readLabeled, csvEscape } = require("./csv.js");
const [inp, out] = process.argv.slice(2);
if (!inp || !out) { console.error("Usage: node eval/export_features.js <urls.csv> <features.csv>"); process.exit(1); }
const rows = readLabeled(inp);
const lines = [["url", "label", ...R.FEATURE_NAMES].join(",")];
let skipped = 0;
for (const r of rows) {
  const f = R.extractUrlFeatures(r.url);
  if (!f) { skipped++; continue; }
  lines.push([csvEscape(r.url), r.label, ...R.FEATURE_NAMES.map((n) => +f[n].toFixed(5))].join(","));
}
fs.writeFileSync(out, lines.join("\n"));
console.log(`Wrote ${lines.length - 1} rows to ${out} (skipped ${skipped} unparsable URLs)`);
