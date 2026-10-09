/**
 * PromptShield AI — Analytics
 * Builds a query string from the filter controls, calls /api/analytics,
 * and renders the metrics row + charts. Re-fetches whenever filters change.
 */

let analyticsCharts = {};

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("applyFiltersBtn").addEventListener("click", loadAnalytics);
  document.getElementById("clearFiltersBtn").addEventListener("click", () => {
    ["filterAttackType", "filterRiskLevel", "filterDefenseMode"].forEach((id) => {
      document.getElementById(id).value = "all";
    });
    document.getElementById("filterStartDate").value = "";
    document.getElementById("filterEndDate").value = "";
    loadAnalytics();
  });
  loadAnalytics();
});

function buildQuery() {
  const params = new URLSearchParams();
  const attackType = document.getElementById("filterAttackType").value;
  const riskLevel = document.getElementById("filterRiskLevel").value;
  const defenseMode = document.getElementById("filterDefenseMode").value;
  const startDate = document.getElementById("filterStartDate").value;
  const endDate = document.getElementById("filterEndDate").value;

  if (attackType && attackType !== "all") params.set("attack_type", attackType);
  if (riskLevel && riskLevel !== "all") params.set("risk_level", riskLevel);
  if (defenseMode && defenseMode !== "all") params.set("defense_mode", defenseMode);
  if (startDate) params.set("start_date", startDate);
  if (endDate) params.set("end_date", endDate);
  return params.toString();
}

async function loadAnalytics() {
  try {
    const qs = buildQuery();
    const res = await fetch(`/api/analytics${qs ? "?" + qs : ""}`).then((r) => r.json());
    if (!res.success) throw new Error(res.error);
    const d = res.data;

    setText("metricAvgRisk", d.metrics.average_risk);
    setText("metricDetectionRate", d.metrics.detection_rate + "%");
    setText("metricBlockRate", d.metrics.block_rate + "%");
    setText("metricHighRiskRate", d.metrics.high_risk_rate + "%");
    setText("metricDefenseEffectiveness", d.metrics.defense_effectiveness + "%");

    renderChart("chartAttackType", "bar", filterEntries(d.by_attack_type, ["none"]));
    renderChart("chartRiskDist", "doughnut", orderedRiskEntries(d.by_risk_level));
    renderTimeline(d.timeseries);
    renderDefenseChart(d.by_defense_mode);
    renderDetectionMethodsChart(d.detection_methods);
  } catch (e) {
    console.error(e);
  }
}

function filterEntries(obj, exclude) {
  return Object.entries(obj || {}).filter(([k]) => !exclude.includes(k));
}

function orderedRiskEntries(byRiskLevel) {
  const order = ["safe", "low", "medium", "high", "critical"];
  return order.filter((l) => byRiskLevel && byRiskLevel[l]).map((l) => [l, byRiskLevel[l]]);
}

function destroyChart(id) {
  if (analyticsCharts[id]) {
    analyticsCharts[id].destroy();
    delete analyticsCharts[id];
  }
}

function renderChart(canvasId, type, entries) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  destroyChart(canvasId);
  resetCanvas(canvasId);
  const freshCanvas = document.getElementById(canvasId);
  if (!freshCanvas) return;

  if (!entries.length) return renderEmptyState(canvasId);

  const labels = entries.map(([k]) => psFormatLabel(k));
  const data = entries.map(([, v]) => v);

  if (type === "bar") {
    analyticsCharts[canvasId] = PSChart.bar(freshCanvas, labels, data);
  } else if (type === "doughnut") {
    const keys = entries.map(([k]) => k);
    analyticsCharts[canvasId] = PSChart.doughnut(freshCanvas, labels, data, {
      colors: keys.map((k) => PSChart.RISK_LEVEL_COLORS[k]),
    });
  }
}

function renderTimeline(timeseries) {
  const canvasId = "chartTimeline";
  destroyChart(canvasId);
  resetCanvas(canvasId);
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (!timeseries || !timeseries.length) return renderEmptyState(canvasId);
  const labels = timeseries.map((p) => p.date);
  const data = timeseries.map((p) => p.count);
  analyticsCharts[canvasId] = PSChart.line(canvas, labels, [{ label: "Tests", data, color: PSChart.COLORS.cyan }]);
}

function renderDefenseChart(byDefenseMode) {
  const canvasId = "chartDefenseEffectiveness";
  destroyChart(canvasId);
  resetCanvas(canvasId);
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const order = ["disabled", "basic", "standard", "maximum"];
  const labels = order.filter((m) => byDefenseMode && byDefenseMode[m]);
  if (!labels.length) return renderEmptyState(canvasId);
  const data = labels.map((m) => byDefenseMode[m].block_rate);
  analyticsCharts[canvasId] = PSChart.bar(canvas, labels.map(psFormatLabel), data, {
    options: { scales: { y: { max: 100, ticks: { callback: (v) => v + "%" } } } },
  });
}

function renderDetectionMethodsChart(detectionMethods) {
  const canvasId = "chartDetectionMethods";
  destroyChart(canvasId);
  resetCanvas(canvasId);
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const labels = Object.keys(detectionMethods || {});
  if (!labels.length) return renderEmptyState(canvasId);
  const data = labels.map((k) => detectionMethods[k]);
  analyticsCharts[canvasId] = PSChart.bar(canvas, labels.map(psFormatLabel), data, {
    colors: [PSChart.COLORS.cyan, PSChart.COLORS.violet, PSChart.COLORS.blue, PSChart.COLORS.amber],
  });
}

function resetCanvas(canvasId) {
  const old = document.getElementById(canvasId);
  if (!old) return;
  const wrap = old.closest(".chart-canvas-wrap");
  const fresh = document.createElement("canvas");
  fresh.id = canvasId;
  old.replaceWith(fresh);
  // A prior render may have left a "no data" message behind (see
  // renderEmptyState) -- clear it now that we're rendering fresh.
  if (wrap) {
    const msg = wrap.querySelector(".chart-empty-msg");
    if (msg) msg.remove();
  }
}

function renderEmptyState(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const wrap = canvas.closest(".chart-canvas-wrap");
  if (!wrap) return;
  // Hide the canvas rather than destroying it -- resetCanvas() looks it
  // up by id on the next render, so removing it here would permanently
  // strand the chart on "no data" even after filters change to a
  // combination that has results.
  canvas.style.display = "none";
  let msg = wrap.querySelector(".chart-empty-msg");
  if (!msg) {
    msg = document.createElement("div");
    msg.className = "empty-state chart-empty-msg";
    msg.style.paddingTop = "70px";
    msg.textContent = "No data for this filter combination.";
    wrap.appendChild(msg);
  }
}

function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value ?? "--";
}
