/**
 * PromptShield AI — Dashboard
 * Pulls live data from /api/dashboard, /api/analytics, /api/history and
 * renders the SOC stat cards, five Chart.js charts, and the recent
 * security events table. Nothing here is hard-coded.
 */

document.addEventListener("DOMContentLoaded", () => {
  loadStats();
  loadCharts();
  loadRecentEvents();
});

async function loadStats() {
  try {
    const res = await PromptShieldAPI.dashboard();
    const d = res.data;
    setText("statTotalTests", d.total_tests);
    setText("statThreatsDetected", d.threats_detected);
    setText("statThreatsBlocked", d.threats_blocked);
    setText("statHighRisk", d.high_risk_events);
    setText("statAvgRisk", d.average_risk);
  } catch (e) {
    ["statTotalTests", "statThreatsDetected", "statThreatsBlocked", "statHighRisk", "statAvgRisk"].forEach((id) => setText(id, "--"));
  }
}

async function loadCharts() {
  try {
    const res = await PromptShieldAPI.analytics();
    const d = res.data;
    renderAttackTypeChart(d.by_attack_type);
    renderRiskDistChart(d.by_risk_level);
    renderTimelineChart(d.timeseries);
    renderDefenseEffectivenessChart(d.by_defense_mode);
    renderDetectionMethodsChart(d.detection_methods);
  } catch (e) {
    /* if the backend has no data yet, charts simply stay empty */
  }
}

function renderAttackTypeChart(byAttackType) {
  const ctx = document.getElementById("chartAttackType");
  if (!ctx || !byAttackType) return;
  const entries = Object.entries(byAttackType).filter(([k]) => k !== "none");
  const labels = entries.map(([k]) => psFormatLabel(k));
  const data = entries.map(([, v]) => v);
  if (!labels.length) return renderEmptyChart(ctx);
  PSChart.bar(ctx, labels, data);
}

function renderRiskDistChart(byRiskLevel) {
  const ctx = document.getElementById("chartRiskDist");
  if (!ctx || !byRiskLevel) return;
  const order = ["safe", "low", "medium", "high", "critical"];
  const labels = order.filter((l) => byRiskLevel[l]);
  const data = labels.map((l) => byRiskLevel[l]);
  if (!labels.length) return renderEmptyChart(ctx);
  PSChart.doughnut(ctx, labels.map(psFormatLabel), data, {
    colors: labels.map((l) => PSChart.RISK_LEVEL_COLORS[l]),
  });
}

function renderTimelineChart(timeseries) {
  const ctx = document.getElementById("chartTimeline");
  if (!ctx || !timeseries || !timeseries.length) return renderEmptyChart(ctx);
  const labels = timeseries.map((p) => p.date);
  const data = timeseries.map((p) => p.count);
  PSChart.line(ctx, labels, [{ label: "Tests", data, color: PSChart.COLORS.cyan }]);
}

function renderDefenseEffectivenessChart(byDefenseMode) {
  const ctx = document.getElementById("chartDefenseEffectiveness");
  if (!ctx || !byDefenseMode) return;
  const order = ["disabled", "basic", "standard", "maximum"];
  const labels = order.filter((m) => byDefenseMode[m]);
  const data = labels.map((m) => byDefenseMode[m].block_rate);
  if (!labels.length) return renderEmptyChart(ctx);
  PSChart.bar(ctx, labels.map(psFormatLabel), data, {
    options: { scales: { y: { max: 100, ticks: { callback: (v) => v + "%" } } } },
  });
}

function renderDetectionMethodsChart(detectionMethods) {
  const ctx = document.getElementById("chartDetectionMethods");
  if (!ctx || !detectionMethods || !Object.keys(detectionMethods).length) return renderEmptyChart(ctx);
  const labels = Object.keys(detectionMethods);
  const data = labels.map((k) => detectionMethods[k]);
  PSChart.bar(ctx, labels.map(psFormatLabel), data, {
    colors: [PSChart.COLORS.cyan, PSChart.COLORS.violet, PSChart.COLORS.blue, PSChart.COLORS.amber],
  });
}

function renderEmptyChart(ctx) {
  if (!ctx) return;
  const wrap = ctx.closest(".chart-canvas-wrap");
  if (wrap) wrap.innerHTML = `<div class="empty-state" style="padding-top:70px;">Not enough data yet.</div>`;
}

let dashboardRecentTests = [];

async function loadRecentEvents() {
  const body = document.getElementById("recentEventsBody");
  if (!body) return;
  try {
    const res = await fetch("/api/history?page_size=10").then((r) => r.json());
    const tests = res.data || [];
    dashboardRecentTests = tests;
    if (!tests.length) {
      body.innerHTML = `<tr><td colspan="6"><div class="empty-state">No security tests recorded yet.</div></td></tr>`;
      return;
    }
    body.innerHTML = tests.map(rowHtml).join("");
    body.querySelectorAll("tr[data-id]").forEach((tr) => {
      tr.addEventListener("click", () => {
        const test = dashboardRecentTests.find((t) => String(t.id) === tr.dataset.id);
        if (test) window.PromptShieldUI.openTestModal(test);
      });
    });
  } catch (e) {
    body.innerHTML = `<tr><td colspan="6"><div class="empty-state">Could not load recent events.</div></td></tr>`;
  }
}

function rowHtml(t) {
  const detected = t.attack_type && t.attack_type !== "none";
  return `<tr data-id="${t.id}">
    <td>${psFormatTime(t.timestamp)}</td>
    <td>${psEscapeHtml(psFormatLabel(t.attack_type))}</td>
    <td><span class="severity-pill ${psSeverityClass(t.risk_level)}">${psEscapeHtml(t.risk_level || "n/a")}</span></td>
    <td>${t.risk_score ?? "n/a"}</td>
    <td>${detected ? "Detected" : "Clean"}</td>
    <td>${psEscapeHtml(psFormatLabel(t.final_decision))}</td>
  </tr>`;
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? "--";
}

(async()=>{try{const r=await fetch("/api/security-score");const x=await r.json();const d=x.data||{};document.getElementById("securityPostureValue").textContent=d.score==null?(d.status||"NO DATA"):d.score+"/100";document.getElementById("auditIntegrityValue").textContent=d.components?.audit_integrity==null?"NO DATA":(d.components.audit_integrity?"VALID":"FAILED");}catch(e){}})();
