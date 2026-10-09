/**
 * PromptShield AI — Chart.js styling helpers.
 * Centralizes the design-system colors/fonts so Dashboard and Analytics
 * charts look consistent without repeating config in every page script.
 * Requires Chart.js to already be loaded on the page.
 */

const PSChart = (() => {
  const COLORS = {
    cyan: "#2be3f0",
    blue: "#3b7bff",
    violet: "#9b6bff",
    red: "#ff5470",
    green: "#2be0a0",
    amber: "#ffb84d",
    orange: "#ff8a3d",
    textDim: "#97a1b8",
    grid: "rgba(255,255,255,0.06)",
  };

  const RISK_LEVEL_COLORS = {
    safe: COLORS.green,
    low: COLORS.cyan,
    medium: COLORS.amber,
    high: COLORS.orange,
    critical: COLORS.red,
  };

  const PALETTE = [COLORS.cyan, COLORS.violet, COLORS.blue, COLORS.amber, COLORS.red, COLORS.green, COLORS.orange, "#5eead4"];

  if (window.Chart) {
    Chart.defaults.color = COLORS.textDim;
    Chart.defaults.font.family = "'JetBrains Mono', monospace";
    Chart.defaults.font.size = 11;
    Chart.defaults.borderColor = COLORS.grid;
  }

  function baseGrid() {
    return { color: COLORS.grid, drawTicks: false };
  }

  function bar(ctx, labels, data, opts = {}) {
    return new Chart(ctx, {
      type: "bar",
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: opts.colors || labels.map((_, i) => PALETTE[i % PALETTE.length]),
          borderRadius: 6,
          maxBarThickness: 42,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true } },
          y: { grid: baseGrid(), beginAtZero: true, ticks: { precision: 0 } },
        },
        ...opts.options,
      },
    });
  }

  function doughnut(ctx, labels, data, opts = {}) {
    return new Chart(ctx, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{
          data,
          backgroundColor: opts.colors || labels.map((l) => RISK_LEVEL_COLORS[l] || PALETTE[labels.indexOf(l) % PALETTE.length]),
          borderColor: "#05070c",
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: {
          legend: { position: "bottom", labels: { boxWidth: 10, padding: 14, font: { size: 10.5 } } },
        },
        ...opts.options,
      },
    });
  }

  function line(ctx, labels, datasets, opts = {}) {
    return new Chart(ctx, {
      type: "line",
      data: {
        labels,
        datasets: datasets.map((ds, i) => ({
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          pointHoverRadius: 4,
          borderColor: ds.color || PALETTE[i % PALETTE.length],
          backgroundColor: (ds.color || PALETTE[i % PALETTE.length]) + "22",
          ...ds,
        })),
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: datasets.length > 1, position: "bottom", labels: { boxWidth: 10, font: { size: 10.5 } } } },
        scales: {
          x: { grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
          y: { grid: baseGrid(), beginAtZero: true, ticks: { precision: 0 } },
        },
        ...opts.options,
      },
    });
  }

  return { COLORS, RISK_LEVEL_COLORS, PALETTE, bar, doughnut, line };
})();
