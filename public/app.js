async function loadReport() {
  const response = await fetch("sample-report.json");
  const report = await response.json();
  render(report);
}

const form = document.getElementById("scan-form");
const input = document.getElementById("scan-url");
const statusNode = document.getElementById("scan-status");

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) {
    statusNode.textContent = "Paste a GitHub or MCP repository URL first.";
    return;
  }

  const button = form.querySelector("button");
  button.disabled = true;
  button.textContent = "Scanning";
  statusNode.textContent = "Cloning read-only, scanning config files, redacting secrets...";

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || "Scan failed");
    }
    render(payload);
    statusNode.textContent = "Fresh scan complete. Review the verdict before adding this tool.";
  } catch (error) {
    statusNode.textContent = `${error.message}. Static demo is still shown below.`;
  } finally {
    button.disabled = false;
    button.textContent = "Scan";
  }
});

function list(items, id) {
  const node = document.getElementById(id);
  node.innerHTML = "";
  for (const item of items || []) {
    const li = document.createElement("li");
    li.textContent = item;
    node.appendChild(li);
  }
}

function label(text) {
  return String(text).replaceAll("_", " ");
}

function basename(path) {
  return String(path || "").split("/").filter(Boolean).pop() || "local agent tool";
}

function decisionFor(score) {
  if (score >= 70) {
    return { text: "Do not add", detail: "High-risk install", className: "block" };
  }
  if (score >= 25) {
    return { text: "Review first", detail: "Use isolation", className: "sandbox" };
  }
  return { text: "Add carefully", detail: "Low-risk install", className: "allow" };
}

function render(report) {
  const decision = decisionFor(report.risk_score || 0);
  const decisionCard = document.querySelector(".decision-card");
  decisionCard.classList.remove("allow", "sandbox", "block");
  decisionCard.classList.add(decision.className);
  document.getElementById("decision").textContent = decision.text;
  document.getElementById("decision-detail").textContent = decision.detail;
  document.getElementById("risk-score").textContent = report.risk_score;
  document.getElementById("target-name").textContent = report.source_url || basename(report.target);
  document.getElementById("review-mode").textContent = report.gemma_error ? "read-only scan + local fallback review" : "read-only local scan + Gemma 4 review";
  document.getElementById("finding-count").textContent = `${(report.findings || []).length} findings`;

  const review = report.gemma_review || {};
  document.getElementById("summary").textContent = review.summary || "No narrative review found.";
  list(review.top_risks, "top-risks");
  list(review.hardening_plan || review.quick_wins, "hardening-plan");

  const capabilities = document.getElementById("capabilities");
  capabilities.innerHTML = "";
  const entries = Object.entries(report.category_counts || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) {
    const empty = document.createElement("div");
    empty.className = "capability";
    empty.innerHTML = `
      <div>
        <strong>No agent-tool signals</strong>
        <small>No shell, browser, write, secret, or instruction signals were found in scanned files.</small>
      </div>
      <span class="capability-count">0</span>
    `;
    capabilities.appendChild(empty);
  }
  for (const [name, value] of entries) {
    const row = document.createElement("div");
    row.className = "capability";
    row.innerHTML = `
      <div>
        <strong>${label(name)}</strong>
        <small>${capabilityCopy(name)}</small>
      </div>
      <span class="capability-count">${value}</span>
    `;
    capabilities.appendChild(row);
  }

  const findings = document.getElementById("findings");
  findings.innerHTML = "";
  for (const item of report.findings || []) {
    const card = document.createElement("article");
    card.className = "finding";
    card.innerHTML = `
      <div class="finding-header">
        <span class="badge ${item.severity}">${item.severity}</span>
        <strong>${label(item.category)}</strong>
        <code>${item.path}:${item.line}</code>
      </div>
      <code>${escapeHtml(item.evidence)}</code>
      <p class="safe-note">${safeWorkflowNote(item.category)}<small>${item.recommendation}</small></p>
    `;
    findings.appendChild(card);
  }
}

function capabilityCopy(name) {
  return ({
    shell_access: "This can become terminal injection if prompts or repo text steer execution.",
    browser_access: "This can touch sessions, cookies, and logged-in pages if profiles are reused.",
    network_access: "This can move data out of the local workflow if not allowlisted.",
    write_access: "This can alter project files, caches, generated output, or local state.",
    secret_reference: "This may pull credential names into model context or reports.",
    instruction_file: "This can change how coding agents interpret future work.",
  })[name] || "Agent surface signal";
}

function safeWorkflowNote(name) {
  return ({
    shell_access: "Typical risk: terminal injection. Run only in a sandbox or require approval per command.",
    browser_access: "Typical risk: logged-in browser exposure. Use a clean profile with no personal sessions.",
    network_access: "Typical risk: silent exfiltration. Use an outbound allowlist for the tool.",
    write_access: "Typical risk: unwanted file changes. Start read-only and narrow writable paths.",
    secret_reference: "Typical risk: credential leakage. Keep values out of prompts, reports, and logs.",
    instruction_file: "Typical risk: prompt steering. Treat repo instructions as untrusted until reviewed.",
  })[name] || "Review this signal before installing the tool globally.";
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  })[char]);
}

loadReport().catch((error) => {
  document.getElementById("summary").textContent = error.message;
});
