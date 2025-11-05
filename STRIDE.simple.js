// document.addEventListener("DOMContentLoaded", () => {
//   const root = document.getElementById("root");

//   const threats = {
//     Spoofing: [
//       { name: "Exposed API Key", score: 10 },
//       { name: "No Extension Verification", score: 7 },
//       { name: "Content Script Injection Bypass", score: 5 },
//     ],
//     Tampering: [
//       { name: "Unvalidated Message Handlers", score: 9 },
//       { name: "Unsafe Storage", score: 6 },
//       { name: "No Favicon URL Sanitization", score: 7 },
//     ],
//     Repudiation: [
//       { name: "No Audit Logging", score: 5 },
//       { name: "No Error Tracking", score: 3 },
//     ],
//     "Information Disclosure": [
//       { name: "Browsing History Exposure", score: 9 },
//       { name: "API Key in Network Traffic", score: 7 },
//       { name: "Console Logging Sensitive Data", score: 5 },
//       { name: "Favicon Hash Privacy", score: 3 },
//     ],
//     "Denial of Service": [
//       { name: "Excessive API Requests", score: 7 },
//       { name: "Memory Leak from MutationObserver", score: 5 },
//       { name: "Recursive Link Scanning", score: 5 },
//     ],
//     "Privilege Escalation": [
//       { name: "Excessive Permissions", score: 7 },
//       { name: "Content Script on All Pages", score: 6 },
//       { name: "No CSP", score: 5 },
//       { name: "Unrestricted Script Injection", score: 7 },
//     ],
//   };

//   const maxScores = {
//     Spoofing: 30,
//     Tampering: 30,
//     Repudiation: 20,
//     "Information Disclosure": 40,
//     "Denial of Service": 30,
//     "Privilege Escalation": 40,
//   };

//   const getSeverityColor = (score) => {
//     if (score >= 9) return "critical";
//     if (score >= 6) return "high";
//     if (score >= 4) return "medium";
//     return "low";
//   };

//   function calculateScores() {
//     let total = 0;
//     let max = 0;
//     let counts = { critical: 0, high: 0, medium: 0, low: 0 };
//     for (const [_, list] of Object.entries(threats)) {
//       for (const t of list) {
//         total += t.score;
//         if (t.score >= 9) counts.critical++;
//         else if (t.score >= 6) counts.high++;
//         else if (t.score >= 4) counts.medium++;
//         else counts.low++;
//       }
//     }
//     for (const val of Object.values(maxScores)) max += val;
//     return { total, max, counts };
//   }

//   function getRiskLevel(percentage) {
//     if (percentage >= 76) return { text: "CRITICAL", color: "critical" };
//     if (percentage >= 51) return { text: "HIGH", color: "high" };
//     if (percentage >= 26) return { text: "MEDIUM", color: "medium" };
//     return { text: "LOW", color: "low" };
//   }

//   const { total, max, counts } = calculateScores();
//   const percentage = Math.round((total / max) * 100);
//   const risk = getRiskLevel(percentage);

//   root.innerHTML = `
//     <div class="dashboard">
//       <h1 class="title">STRIDE Risk Score Calculator</h1>
//       <p class="subtitle">Track security improvements for SecureSight Extension</p>

//       <div class="summary-card">
//         <div class="summary-item">
//           <div class="summary-icon ${risk.color}"></div>
//           <div>
//             <h2 class="${risk.color}">${risk.text}</h2>
//             <p>Risk Level</p>
//           </div>
//         </div>
//         <div class="summary-stat">
//           <h2>${total}</h2>
//           <p>Total Score / ${max}</p>
//         </div>
//         <div class="summary-stat">
//           <h2 class="${risk.color}">${percentage}%</h2>
//           <p>Risk Percentage</p>
//         </div>
//         <div class="summary-stat">
//           <h2>${Object.values(threats).flat().length}</h2>
//           <p>Active Threats</p>
//         </div>
//       </div>

//       <div class="risk-tags">
//         <span class="tag critical">🔴 Critical: ${counts.critical}</span>
//         <span class="tag high">🟠 High: ${counts.high}</span>
//         <span class="tag medium">🟡 Medium: ${counts.medium}</span>
//         <span class="tag low">🟢 Low: ${counts.low}</span>
//       </div>

//       ${Object.entries(threats)
//         .map(([cat, list]) => {
//           const catScore = list.reduce((s, t) => s + t.score, 0);
//           const catMax = maxScores[cat];
//           const percent = Math.round((catScore / catMax) * 100);
//           return `
//           <div class="category-card">
//             <div class="category-header">
//               <h3>${cat}</h3>
//               <span class="category-score">Score: ${catScore}/${catMax}</span>
//             </div>
//             <div class="progress-bar"><div class="progress" style="width:${percent}%"></div></div>
//             <div class="threats">
//               ${list
//                 .map(
//                   (t) => `
//                   <div class="threat ${getSeverityColor(t.score)}">
//                     <span>❌ ${t.name}</span>
//                     <span class="score-label">${t.score}/10</span>
//                   </div>`
//                 )
//                 .join("")}
//             </div>
//           </div>`;
//         })
//         .join("")}

//       <div class="guide">
//         <h4>Risk Level Guide</h4>
//         <div class="guide-levels">
//           <div class="level low">🟢 LOW (0–25%)<p>Minimal security concerns</p></div>
//           <div class="level medium">🟡 MEDIUM (26–50%)<p>Some vulnerabilities present</p></div>
//           <div class="level high">🟠 HIGH (51–75%)<p>Significant security risks</p></div>
//           <div class="level critical">🔴 CRITICAL (76–100%)<p>Immediate action required</p></div>
//         </div>
//       </div>
//     </div>
//   `;
// });

let loadedFiles = {};
const fileInput = document.getElementById("fileInput");
const uploadBtn = document.getElementById("uploadBtn");
const analyzeBtn = document.getElementById("analyzeBtn");
const fileInfo = document.getElementById("fileInfo");
const loading = document.getElementById("loading");
const results = document.getElementById("results");

uploadBtn.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", handleFileUpload);
analyzeBtn.addEventListener("click", () => analyzeFiles(loadedFiles));

function handleFileUpload(e) {
  const files = Array.from(e.target.files);
  let loaded = 0;

  files.forEach((file) => {
    const reader = new FileReader();
    reader.onload = (event) => {
      loadedFiles[file.name] = event.target.result;
      loaded++;

      if (loaded === files.length) {
        updateFileInfo();
        analyzeFiles(loadedFiles);
      }
    };
    reader.readAsText(file);
  });
}

function updateFileInfo() {
  const fileNames = Object.keys(loadedFiles);
  fileInfo.textContent =
    fileNames.length === 0 ? "No files loaded" : `Loaded: ${fileNames.join(", ")}`;
}

function analyzeFiles(files) {
  if (Object.keys(files).length === 0) {
    alert("Please upload extension files first!");
    return;
  }

  loading.classList.remove("hidden");
  results.innerHTML = "";

  setTimeout(() => {
    results.innerHTML = analyzeThreats(files);
    loading.classList.add("hidden");
  }, 600);
}

/* -------------------------------
   🔍 STRIDE ANALYSIS LOGIC
--------------------------------*/
function analyzeThreats(files) {
  const threats = {
    Spoofing: [],
    Tampering: [],
    Repudiation: [],
    "Information Disclosure": [],
    "Denial of Service": [],
    "Privilege Escalation": []
  };

  // ---------- Detection Rules ----------
  for (const [filename, content] of Object.entries(files)) {
    // Spoofing
    if (content.includes("apiKey") || content.match(/AIza|sk-|ghp_/))
      threats.Spoofing.push({ name: "Exposed API Key", score: 10 });

    // Tampering
    if (content.includes("eval("))
      threats.Tampering.push({ name: "Use of eval()", score: 7 });
    if (content.includes("innerHTML"))
      threats.Tampering.push({ name: "Unsanitized DOM manipulation", score: 5 });

    // Repudiation
    if (content.includes("console.log"))
      threats.Repudiation.push({ name: "Debug Logging in Production", score: 3 });

    // Info Disclosure
    if (content.includes("password") || content.includes("secret"))
      threats["Information Disclosure"].push({ name: "Sensitive keyword exposed", score: 8 });

    // DoS
    if (content.includes("while(true)") || content.includes("setInterval("))
      threats["Denial of Service"].push({ name: "Infinite Loop / Flood Risk", score: 6 });

    // Privilege Escalation
    if (filename === "manifest.json" && !content.includes('"content_security_policy"'))
      threats["Privilege Escalation"].push({ name: "No CSP", score: 5 });
    if (content.includes("document.write"))
      threats["Privilege Escalation"].push({ name: "DOM Manipulation", score: 2 });
  }

  // ---------- Score Computation ----------
  const maxScores = {
    Spoofing: 30,
    Tampering: 30,
    Repudiation: 20,
    "Information Disclosure": 40,
    "Denial of Service": 30,
    "Privilege Escalation": 40,
  };

  const getSeverityColor = (score) => {
    if (score >= 9) return "critical";
    if (score >= 6) return "high";
    if (score >= 4) return "medium";
    return "low";
  };

  const calculateScores = () => {
    let total = 0;
    let max = 0;
    let counts = { critical: 0, high: 0, medium: 0, low: 0 };

    for (const list of Object.values(threats)) {
      for (const t of list) {
        total += t.score;
        if (t.score >= 9) counts.critical++;
        else if (t.score >= 6) counts.high++;
        else if (t.score >= 4) counts.medium++;
        else counts.low++;
      }
    }

    for (const val of Object.values(maxScores)) max += val;
    return { total, max, counts };
  };

  const getRiskLevel = (percentage) => {
    if (percentage >= 76) return { text: "CRITICAL", color: "critical" };
    if (percentage >= 51) return { text: "HIGH", color: "high" };
    if (percentage >= 26) return { text: "MEDIUM", color: "medium" };
    return { text: "LOW", color: "low" };
  };

  const { total, max, counts } = calculateScores();
  const percentage = Math.round((total / max) * 100);
  const risk = getRiskLevel(percentage);

  // ---------- Render Dashboard ----------
  return `
    <div class="dashboard">
      <h1 class="title">STRIDE Risk Score Calculator</h1>
      <p class="subtitle">Track security improvements for SecureSight Extension</p>

      <div class="summary-card">
        <div class="summary-item">
          <div class="summary-icon ${risk.color}"></div>
          <div>
            <h2 class="${risk.color}">${risk.text}</h2>
            <p>Risk Level</p>
          </div>
        </div>
        <div class="summary-stat"><h2>${total}</h2><p>Total Score / ${max}</p></div>
        <div class="summary-stat"><h2 class="${risk.color}">${percentage}%</h2><p>Risk Percentage</p></div>
        <div class="summary-stat"><h2>${Object.values(threats).flat().length}</h2><p>Threats Analyzed</p></div>
      </div>

      <div class="risk-tags">
        <span class="tag critical">🔴 Critical: ${counts.critical}</span>
        <span class="tag high">🟠 High: ${counts.high}</span>
        <span class="tag medium">🟡 Medium: ${counts.medium}</span>
        <span class="tag low">🟢 Low: ${counts.low}</span>
      </div>

      ${Object.entries(threats)
        .map(([cat, list]) => {
          const catScore = list.reduce((s, t) => s + t.score, 0);
          const catMax = maxScores[cat];
          const percent = Math.round((catScore / catMax) * 100);
          return `
          <div class="category-card">
            <div class="category-header">
              <h3>${cat}</h3>
              <span class="category-score">Score: ${catScore}/${catMax}</span>
            </div>
            <div class="progress-bar"><div class="progress" style="width:${percent}%"></div></div>
            <div class="threats">
              ${
                list.length
                  ? list
                      .map(
                        (t) => `
                        <div class="threat ${getSeverityColor(t.score)}">
                          <span>❌ ${t.name}</span>
                          <span class="score-label">${t.score}/10</span>
                        </div>`
                      )
                      .join("")
                  : "<p>No threats detected in this category.</p>"
              }
            </div>
          </div>`;
        })
        .join("")}

      <div class="guide">
        <h4>Risk Level Guide</h4>
        <div class="guide-levels">
          <div class="level low">🟢 LOW (0–25%)<p>Minimal security concerns</p></div>
          <div class="level medium">🟡 MEDIUM (26–50%)<p>Some vulnerabilities present</p></div>
          <div class="level high">🟠 HIGH (51–75%)<p>Significant security risks</p></div>
          <div class="level critical">🔴 CRITICAL (76–100%)<p>Immediate action required</p></div>
        </div>
      </div>
    </div>
  `;
}
