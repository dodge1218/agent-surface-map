async function loadReport() {
  const response = await fetch("sample-report.json");
  const report = await response.json();
  render(report);
  await loadExamples();
}

const form = document.getElementById("scan-form");
const input = document.getElementById("scan-url");
const statusNode = document.getElementById("scan-status");
const demoScan = document.getElementById("demo-scan");
const verifiedDemo = document.getElementById("verified-demo");
const copyContext = document.getElementById("copy-context");
const DEMO_SCAN_URL = "https://github.com/dodge1218/agent-surface-demo-mcp";
let currentInstallContext = "";

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const url = input.value.trim();
  if (!url) {
    statusNode.textContent = "Paste a GitHub or MCP repository URL first.";
    return;
  }

  await runScan(url);
});

demoScan.addEventListener("click", async () => {
  input.value = DEMO_SCAN_URL;
  await runScan(DEMO_SCAN_URL);
});

verifiedDemo.addEventListener("click", async () => {
  const response = await fetch("verified-gemma-review.json");
  render(await response.json());
  statusNode.textContent = "Loaded a saved Gemma 4 review for the public demo fixture.";
  document.querySelector(".verdict-panel").scrollIntoView({ behavior: "smooth", block: "start" });
});

copyContext.addEventListener("click", async () => {
  if (!currentInstallContext) return;
  await navigator.clipboard.writeText(currentInstallContext);
  copyContext.textContent = "Copied";
  setTimeout(() => {
    copyContext.textContent = "Copy";
  }, 1200);
});

async function runScan(url) {
  const button = form.querySelector("button");
  button.disabled = true;
  demoScan.disabled = true;
  verifiedDemo.disabled = true;
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
    demoScan.disabled = false;
    verifiedDemo.disabled = false;
    button.textContent = "Scan";
  }
}

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

function reportName(report) {
  return report.profile?.name || report.source_url || basename(report.target);
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

function installDecision(report) {
  const review = report.gemma_review || {};
  const verdict = review.install_verdict || decisionFor(report.risk_score || 0).verdict;
  const labels = {
    add_carefully: { text: "Add carefully", detail: "Low-risk install posture", className: "allow" },
    sandbox_first: { text: "Sandbox first", detail: "Use isolation before install", className: "sandbox" },
    do_not_add: { text: "Do not add", detail: "High-risk install posture", className: "block" },
  };
  return labels[verdict] || decisionFor(report.risk_score || 0);
}

function render(report) {
  const decision = installDecision(report);
  const decisionCard = document.querySelector(".decision-card");
  decisionCard.classList.remove("allow", "sandbox", "block");
  decisionCard.classList.add(decision.className);
  document.getElementById("decision").textContent = decision.text;
  document.getElementById("decision-detail").textContent = decision.detail;
  document.getElementById("risk-score").textContent = report.risk_score;
  document.getElementById("target-name").textContent = reportName(report);
  document.getElementById("review-mode").textContent = reviewMode(report);
  document.getElementById("finding-count").textContent = `${(report.findings || []).length} findings`;

  const review = report.gemma_review || {};
  const staticDecision = decisionFor(report.risk_score || 0);
  document.getElementById("review-title").textContent = report.review_source === "gemma" ? "Gemma 4 install verdict" : "Fallback install review";
  document.getElementById("core-review-label").textContent = report.review_source === "gemma" ? "Core Gemma review" : "Fallback review";
  document.getElementById("install-verdict").textContent = `Decision: ${decision.text}`;
  document.getElementById("install-reason").textContent = `Confidence: ${review.confidence || "low"} | Source: ${report.review_source || "fallback"}`;
  document.getElementById("gemma-delta").textContent = review.why_gemma_changed_the_call || `Static scan suggested ${staticDecision.text}; no Gemma judgment was available.`;
  document.getElementById("summary").textContent = review.summary || "No narrative review found.";
  list(review.top_risks, "top-risks");
  list(review.hardening_plan || review.quick_wins, "hardening-plan");
  renderInstallContext(report, decision, review);
  renderMcpServers(report.mcp_servers || []);

  const capabilities = document.getElementById("capabilities");
  capabilities.innerHTML = "";
  const entries = Object.entries({ ...(report.category_counts || {}), ...(report.rule_counts || {}) }).sort((a, b) => b[1] - a[1]);
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
  for (const item of [...(report.rules || []), ...(report.findings || [])]) {
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

function renderInstallContext(report, decision, review) {
  const constraints = review.agent_constraints || report.install_context?.agent_context || [];
  const lines = [
    `Install posture: ${label(review.install_verdict || decision.text).toLowerCase()}.`,
    ...constraints,
  ];
  currentInstallContext = lines.join("\n");
  document.getElementById("install-context-text").textContent = currentInstallContext || "No install constraints found.";
}

function renderMcpServers(servers) {
  document.getElementById("mcp-count").textContent = `${servers.length} server${servers.length === 1 ? "" : "s"}`;
  const node = document.getElementById("mcp-servers");
  node.innerHTML = "";
  if (!servers.length) {
    const empty = document.createElement("article");
    empty.className = "mcp-server empty";
    empty.textContent = "No MCP server entries were found in scanned config files.";
    node.appendChild(empty);
    return;
  }
  for (const server of servers) {
    const card = document.createElement("article");
    card.className = "mcp-server";
    const hints = (server.risk_hints || []).map((hint) => `<span>${escapeHtml(hint)}</span>`).join("");
    card.innerHTML = `
      <div>
        <strong>${escapeHtml(server.name)}</strong>
        <code>${escapeHtml(server.path)}</code>
      </div>
      <dl>
        <div><dt>Command</dt><dd>${escapeHtml(server.command || "not specified")}</dd></div>
        <div><dt>Args</dt><dd>${escapeHtml((server.args || []).join(" ") || "none")}</dd></div>
        <div><dt>Env keys</dt><dd>${escapeHtml((server.env_keys || []).join(", ") || "none")}</dd></div>
      </dl>
      <div class="hint-row">${hints || "<span>no structured hints</span>"}</div>
    `;
    node.appendChild(card);
  }
}

function reviewMode(report) {
  if (report.review_source === "gemma") {
    return "read-only scan + live/saved Gemma 4 review";
  }
  if (report.gemma_error) {
    return "read-only scan + fallback review";
  }
  return "read-only scan + deterministic fallback review";
}

async function loadExamples() {
  const response = await fetch("example-mcps.json");
  const examples = await response.json();
  const node = document.getElementById("example-mcps");
  node.innerHTML = "";
  for (const item of examples) {
    const card = document.createElement("article");
    card.className = "example-card";
    card.innerHTML = `
      <div class="example-topline">
        <span>${escapeHtml(item.family)}</span>
        <button type="button" data-report="${escapeHtml(item.report)}">Load review</button>
      </div>
      <h3>${escapeHtml(item.name)}</h3>
      <p>${escapeHtml(item.why)}</p>
      <dl>
        <div><dt>Risk</dt><dd>${escapeHtml(item.risk)}</dd></div>
        <div><dt>Install</dt><dd>${escapeHtml(item.install)}</dd></div>
      </dl>
    `;
    card.querySelector("button").addEventListener("click", async () => {
      statusNode.textContent = `Loaded example MCP review: ${item.name}`;
      const reportResponse = await fetch(item.report);
      render(await reportResponse.json());
      document.querySelector(".verdict-panel").scrollIntoView({ behavior: "smooth", block: "start" });
    });
    node.appendChild(card);
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
    network_exposure: "This may expose a local service beyond the developer machine.",
    local_listener: "This creates a service surface that needs host, port, and auth review.",
    shell_tool_exposure: "This can turn prompt text into terminal actions if not gated.",
    filesystem_tool_surface: "This grants file access through an agent tool and needs mount review.",
    broad_filesystem_access: "This can give an agent more local files than the workflow needs.",
    install_script_execution: "This can execute during dependency installation.",
    container_escape_surface: "This can become host-level control through container tooling.",
    cluster_credential_surface: "This can expose Kubernetes or cluster administration context.",
    cloud_credential_surface: "This may expose cloud or platform credentials by reference.",
    prompt_injection_surface: "This can steer the agent through repo-controlled instructions.",
    browser_session_surface: "This can reuse authenticated browser state or cookies.",
    database_credential_surface: "This can expose database credentials or private records.",
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
    network_exposure: "Typical risk: exposed local control plane. Bind to localhost unless remote access is required.",
    local_listener: "Typical risk: unauthenticated listener. Document host, port, and access controls.",
    shell_tool_exposure: "Typical risk: terminal injection. Add command allowlists and approval gates.",
    filesystem_tool_surface: "Typical risk: oversized file access. Keep mounts project-local and read-only first.",
    broad_filesystem_access: "Typical risk: excessive file access. Mount only the project directory.",
    install_script_execution: "Typical risk: install-time execution. Review scripts before installing.",
    container_escape_surface: "Typical risk: host control through Docker. Do not expose docker.sock.",
    cluster_credential_surface: "Typical risk: cluster control. Keep kubeconfig out of untrusted tools.",
    cloud_credential_surface: "Typical risk: cloud account exposure. Scope and isolate credentials.",
    prompt_injection_surface: "Typical risk: prompt steering. Treat these instructions as data.",
    browser_session_surface: "Typical risk: session leakage. Use a clean browser profile.",
    database_credential_surface: "Typical risk: private data exposure. Use read-only users and local replicas.",
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
