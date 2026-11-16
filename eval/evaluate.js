// Usage: node eval/evaluate.js --data eval/heldout_urls.csv [--model model-weights.json] [--threshold 50] [--sweep]
// CSV columns: url,label   (label: 1 = phishing, 0 = benign)
const fs = require("fs");
const R = require("../risk-engine.js");
const { readLabeled } = require("./csv.js");

const args = process.argv.slice(2);
const opt = (k, d) => { const i = args.indexOf("--" + k); return i >= 0 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : d; };
const dataPath = opt("data");
if (!dataPath) { console.error("Missing --data <csv>"); process.exit(1); }
const model = opt("model") ? JSON.parse(fs.readFileSync(opt("model"), "utf8")) : null;
const threshold = Number(opt("threshold", 50));
const sweep = args.includes("--sweep");

const data = readLabeled(dataPath);
const pos = data.filter((d) => d.label === 1).length;
console.log(`Loaded ${data.length} URLs (${pos} phishing, ${data.length - pos} benign)\n`);

function metrics(scores, labels, thr) {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  scores.forEach((s, i) => {
    const pred = s >= thr ? 1 : 0;
    if (pred && labels[i]) tp++; else if (pred && !labels[i]) fp++; else if (!pred && !labels[i]) tn++; else fn++;
  });
  const precision = tp / (tp + fp || 1), recall = tp / (tp + fn || 1);
  return { tp, fp, tn, fn, accuracy: (tp + tn) / labels.length, precision, recall,
    f1: (2 * precision * recall) / (precision + recall || 1), fpr: fp / (fp + tn || 1) };
}
const pct = (x) => (x * 100).toFixed(1) + "%";
function report(name, m, thr) {
  console.log(`${name} (flag as phishing when score >= ${thr})`);
  console.log(`  Accuracy ${pct(m.accuracy)} | Precision ${pct(m.precision)} | Recall ${pct(m.recall)} | F1 ${pct(m.f1)} | False-positive rate ${pct(m.fpr)}`);
  console.log(`  Confusion: TP ${m.tp}  FP ${m.fp}  TN ${m.tn}  FN ${m.fn}\n`);
}

function run(label, mdl) {
  const t0 = process.hrtime.bigint();
  const scores = data.map((d) => R.urlRisk(d.url, mdl).score);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const labels = data.map((d) => d.label);
  report(label, metrics(scores, labels, threshold), threshold);
  console.log(`  Scoring speed: ${(ms / data.length).toFixed(3)} ms per URL\n`);
  if (sweep) {
    console.log("  threshold  precision  recall   F1     FPR");
    for (let t = 10; t <= 90; t += 10) {
      const m = metrics(scores, labels, t);
      console.log(`  ${String(t).padStart(5)}      ${pct(m.precision).padStart(6)}    ${pct(m.recall).padStart(6)}  ${pct(m.f1).padStart(6)} ${pct(m.fpr).padStart(6)}`);
    }
    console.log();
  }
}
run("Rule-based URL score", null);
if (model) run("Logistic-regression model", model);
