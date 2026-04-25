import { Finding } from "../findings/finding.js";
import { ReportingConfig } from "../core/config.loader.js";
import { AttackAnalyzer, SecurityVerdict } from "../findings/attack.analyzer.js";
import { sortByRisk } from "../findings/normalizer.js";

export interface HtmlReporterOptions {
  targetUrl: string;
  scanDuration?: number;
  verdict?: SecurityVerdict;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#65a30d",
};

const VERDICT_STYLE: Record<string, { bg: string; border: string; label: string; icon: string }> = {
  UNSAFE: { bg: "#fef2f2", border: "#dc2626", label: "UNSAFE TO DEPLOY", icon: "⛔" },
  REVIEW_REQUIRED: { bg: "#fffbeb", border: "#d97706", label: "REVIEW REQUIRED", icon: "⚠️" },
  INCONCLUSIVE: { bg: "#f5f3ff", border: "#7c3aed", label: "SCAN INCOMPLETE", icon: "❓" },
  SAFE: { bg: "#f0fdf4", border: "#16a34a", label: "SAFE TO DEPLOY", icon: "✅" },
};

function esc(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export class HtmlReporter {
  private attackAnalyzer: AttackAnalyzer;

  constructor(_config: ReportingConfig) {
    this.attackAnalyzer = new AttackAnalyzer();
  }

  generate(findings: Finding[], options: HtmlReporterOptions): string {
    const verdict = options.verdict ?? this.attackAnalyzer.generateVerdict(findings);
    const sorted = sortByRisk(findings);
    const timestamp = new Date().toISOString();
    const duration = options.scanDuration
      ? `${(options.scanDuration / 1000).toFixed(1)}s`
      : "";

    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1;
    }

    const vs = VERDICT_STYLE[verdict.verdict] ?? VERDICT_STYLE.INCONCLUSIVE;

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Breach Gate Security Report — ${esc(options.targetUrl)}</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; line-height: 1.5; }
  a { color: #2563eb; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
  header { background: #0f172a; color: white; padding: 16px 0; margin-bottom: 24px; }
  header .wrap { display: flex; align-items: center; gap: 12px; }
  .logo { font-size: 1.4rem; font-weight: 700; letter-spacing: -0.5px; }
  .logo span { color: #f59e0b; }
  .meta { font-size: 0.8rem; color: #94a3b8; margin-left: auto; text-align: right; }

  .verdict-box {
    border: 2px solid ${vs.border};
    background: ${vs.bg};
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .verdict-icon { font-size: 2.5rem; line-height: 1; }
  .verdict-label { font-size: 1.5rem; font-weight: 700; color: ${vs.border}; }
  .verdict-reason { font-size: 0.9rem; color: #475569; margin-top: 4px; }
  .verdict-breach { font-weight: 600; color: #dc2626; margin-top: 6px; }

  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 24px; }
  .stat-card { background: white; border-radius: 8px; padding: 16px; border: 1px solid #e2e8f0; text-align: center; }
  .stat-num { font-size: 2rem; font-weight: 700; }
  .stat-label { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 2px; }

  .filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; align-items: center; }
  .filter-btn {
    padding: 5px 14px; border-radius: 20px; border: 1px solid #cbd5e1;
    background: white; cursor: pointer; font-size: 0.8rem; font-weight: 500; color: #475569;
    transition: all 0.15s;
  }
  .filter-btn:hover { border-color: #94a3b8; background: #f1f5f9; }
  .filter-btn.active { color: white; border-color: transparent; }
  .filter-btn.active[data-sev="ALL"] { background: #0f172a; }
  .filter-btn.active[data-sev="CRITICAL"] { background: #dc2626; }
  .filter-btn.active[data-sev="HIGH"] { background: #ea580c; }
  .filter-btn.active[data-sev="MEDIUM"] { background: #d97706; }
  .filter-btn.active[data-sev="LOW"] { background: #65a30d; }
  .search { margin-left: auto; padding: 5px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.85rem; width: 220px; }
  .search:focus { outline: none; border-color: #2563eb; }

  .finding-card {
    background: white; border: 1px solid #e2e8f0; border-radius: 10px;
    margin-bottom: 10px; overflow: hidden;
  }
  .finding-header {
    display: flex; align-items: center; gap: 12px; padding: 14px 18px;
    cursor: pointer; user-select: none;
  }
  .finding-header:hover { background: #f8fafc; }
  .sev-badge {
    font-size: 0.7rem; font-weight: 700; padding: 2px 8px; border-radius: 4px;
    color: white; text-transform: uppercase; letter-spacing: 0.05em; flex-shrink: 0;
  }
  .finding-title { font-weight: 600; font-size: 0.95rem; flex: 1; }
  .finding-endpoint { font-size: 0.8rem; color: #64748b; font-family: monospace; }
  .finding-confirmed { font-size: 0.75rem; color: #dc2626; font-weight: 600; margin-left: 4px; }
  .chevron { color: #94a3b8; transition: transform 0.2s; flex-shrink: 0; }
  .finding-card.open .chevron { transform: rotate(180deg); }
  .finding-body { display: none; padding: 0 18px 16px; border-top: 1px solid #f1f5f9; }
  .finding-card.open .finding-body { display: block; }
  .finding-body dt { font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 12px; }
  .finding-body dd { font-size: 0.9rem; margin-top: 3px; }
  .evidence { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 10px 12px; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; margin-top: 4px; color: #334155; }
  .cve-link { font-family: monospace; font-size: 0.85rem; }

  .empty { text-align: center; padding: 48px; color: #64748b; }
  .section-title { font-size: 1rem; font-weight: 600; color: #374151; margin-bottom: 12px; margin-top: 28px; }
  footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e2e8f0; font-size: 0.8rem; color: #94a3b8; text-align: center; }
</style>
</head>
<body>
<header>
  <div class="wrap">
    <div class="logo">Breach<span>Gate</span></div>
    <div class="meta">
      <div>${esc(options.targetUrl)}</div>
      <div>${timestamp}${duration ? ` · ${duration}` : ""}</div>
    </div>
  </div>
</header>

<div class="wrap">

  <div class="verdict-box">
    <div class="verdict-icon">${vs.icon}</div>
    <div>
      <div class="verdict-label">${vs.label}</div>
      <div class="verdict-reason">${esc(verdict.reason)}</div>
      ${verdict.operationalConclusion ? `<div class="verdict-breach">Breach: ${esc(verdict.operationalConclusion)}</div>` : ""}
    </div>
  </div>

  <div class="stats">
    <div class="stat-card">
      <div class="stat-num">${findings.length}</div>
      <div class="stat-label">Total Findings</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:${SEVERITY_COLOR.CRITICAL}">${counts.CRITICAL}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:${SEVERITY_COLOR.HIGH}">${counts.HIGH}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:${SEVERITY_COLOR.MEDIUM}">${counts.MEDIUM}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:${SEVERITY_COLOR.LOW}">${counts.LOW}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card">
      <div class="stat-num" style="color:#dc2626">${verdict.confirmedExploits.length}</div>
      <div class="stat-label">Confirmed Exploits</div>
    </div>
  </div>

  ${sorted.length === 0 ? `
  <div class="empty">
    <div style="font-size:2.5rem;margin-bottom:8px">✅</div>
    <div>No security findings detected.</div>
  </div>` : `
  <div class="filters">
    <button class="filter-btn active" data-sev="ALL">All (${findings.length})</button>
    ${counts.CRITICAL > 0 ? `<button class="filter-btn" data-sev="CRITICAL">Critical (${counts.CRITICAL})</button>` : ""}
    ${counts.HIGH > 0 ? `<button class="filter-btn" data-sev="HIGH">High (${counts.HIGH})</button>` : ""}
    ${counts.MEDIUM > 0 ? `<button class="filter-btn" data-sev="MEDIUM">Medium (${counts.MEDIUM})</button>` : ""}
    ${counts.LOW > 0 ? `<button class="filter-btn" data-sev="LOW">Low (${counts.LOW})</button>` : ""}
    <input class="search" type="search" placeholder="Search findings…" aria-label="Search findings">
  </div>

  <div id="findings-list">
    ${sorted.map((f, i) => this.renderFinding(f, i)).join("\n    ")}
  </div>`}

</div>

<footer class="wrap">Generated by <strong>Breach Gate</strong> — Attack Feasibility Analyzer</footer>

<script>
(function () {
  var activeFilter = "ALL";
  var searchQuery = "";

  function applyFilters() {
    var cards = document.querySelectorAll(".finding-card");
    cards.forEach(function (card) {
      var sev = card.getAttribute("data-sev");
      var text = card.getAttribute("data-text") || "";
      var sevMatch = activeFilter === "ALL" || sev === activeFilter;
      var searchMatch = !searchQuery || text.includes(searchQuery.toLowerCase());
      card.style.display = (sevMatch && searchMatch) ? "" : "none";
    });
  }

  document.querySelectorAll(".filter-btn").forEach(function (btn) {
    btn.addEventListener("click", function () {
      activeFilter = btn.getAttribute("data-sev");
      document.querySelectorAll(".filter-btn").forEach(function (b) { b.classList.remove("active"); });
      btn.classList.add("active");
      applyFilters();
    });
  });

  var searchInput = document.querySelector(".search");
  if (searchInput) {
    searchInput.addEventListener("input", function () {
      searchQuery = searchInput.value.toLowerCase();
      applyFilters();
    });
  }

  document.querySelectorAll(".finding-header").forEach(function (header) {
    header.addEventListener("click", function () {
      header.closest(".finding-card").classList.toggle("open");
    });
  });
})();
</script>
</body>
</html>`;
  }

  private renderFinding(f: Finding, index: number): string {
    const color = SEVERITY_COLOR[f.severity] ?? "#64748b";
    const textContent = [f.title, f.category, f.endpoint ?? "", f.evidence ?? ""]
      .join(" ")
      .toLowerCase();
    const isConfirmed = f.sources.includes("AI Security Tester") || f.sources.includes("OWASP ZAP API");

    return `<div class="finding-card" data-sev="${f.severity}" data-text="${esc(textContent)}" id="finding-${index}">
      <div class="finding-header">
        <span class="sev-badge" style="background:${color}">${f.severity}</span>
        <span class="finding-title">${esc(f.title)}</span>
        ${f.endpoint ? `<span class="finding-endpoint">${esc(f.endpoint)}</span>` : ""}
        ${isConfirmed ? `<span class="finding-confirmed">CONFIRMED</span>` : ""}
        <svg class="chevron" width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </div>
      <div class="finding-body">
        <dl>
          <dt>Category</dt><dd>${esc(f.category)}</dd>
          ${f.evidence ? `<dt>Evidence</dt><dd><div class="evidence">${esc(f.evidence)}</div></dd>` : ""}
          ${f.sources.length > 0 ? `<dt>Source</dt><dd>${esc(f.sources.join(", "))}</dd>` : ""}
          ${f.cve ? `<dt>CVE</dt><dd><a class="cve-link" href="https://nvd.nist.gov/vuln/detail/${esc(f.cve)}" target="_blank" rel="noopener">${esc(f.cve)}</a></dd>` : ""}
          ${f.cwe ? `<dt>CWE</dt><dd>${esc(f.cwe)}</dd>` : ""}
          ${f.package ? `<dt>Package</dt><dd>${esc(f.package)}${f.version ? ` @ ${esc(f.version)}` : ""}${f.fixedVersion ? ` → fix: ${esc(f.fixedVersion)}` : ""}</dd>` : ""}
        </dl>
      </div>
    </div>`;
  }
}
