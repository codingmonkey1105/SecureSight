// Minimal RFC-4180 CSV reader (handles quoted fields containing commas).
const fs = require("fs");
function parseCsv(text) {
  const rows = []; let row = [], field = "", inQ = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQ) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') inQ = false;
      else field += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== "" || row.length) { row.push(field); rows.push(row); }
  return rows;
}
function readLabeled(path) {
  const rows = parseCsv(fs.readFileSync(path, "utf8"));
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const ui = head.indexOf("url"), li = head.indexOf("label");
  if (ui < 0 || li < 0) throw new Error("CSV needs 'url' and 'label' columns (label: 1 = phishing, 0 = benign)");
  return rows.slice(1).map((r) => ({ url: r[ui], label: Number(r[li]) })).filter((r) => r.url && (r.label === 0 || r.label === 1));
}
function csvEscape(v) { const s = String(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
module.exports = { parseCsv, readLabeled, csvEscape };
