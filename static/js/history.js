/**
 * PromptShield AI — History
 * Drives /api/history with search, filters, column sorting, and
 * pagination. Row click opens the shared detail modal.
 */

const historyState = {
  q: "",
  attack_type: "all",
  risk_level: "all",
  defense_mode: "all",
  sort_by: "timestamp",
  sort_dir: "desc",
  page: 1,
  page_size: 10,
};

let historyRows = [];

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("historySearchBtn").addEventListener("click", () => {
    historyState.q = document.getElementById("historySearch").value.trim();
    historyState.page = 1;
    loadHistory();
  });
  document.getElementById("historySearch").addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      historyState.q = e.target.value.trim();
      historyState.page = 1;
      loadHistory();
    }
  });
  document.getElementById("historyAttackType").addEventListener("change", (e) => {
    historyState.attack_type = e.target.value;
    historyState.page = 1;
    loadHistory();
  });
  document.getElementById("historyRiskLevel").addEventListener("change", (e) => {
    historyState.risk_level = e.target.value;
    historyState.page = 1;
    loadHistory();
  });
  document.getElementById("historyDefenseMode").addEventListener("change", (e) => {
    historyState.defense_mode = e.target.value;
    historyState.page = 1;
    loadHistory();
  });
  document.querySelectorAll("#historyTable th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const field = th.dataset.sort;
      if (historyState.sort_by === field) {
        historyState.sort_dir = historyState.sort_dir === "asc" ? "desc" : "asc";
      } else {
        historyState.sort_by = field;
        historyState.sort_dir = "desc";
      }
      loadHistory();
    });
  });

  loadHistory();
});

function buildHistoryQuery() {
  const params = new URLSearchParams();
  if (historyState.q) params.set("q", historyState.q);
  if (historyState.attack_type !== "all") params.set("attack_type", historyState.attack_type);
  if (historyState.risk_level !== "all") params.set("risk_level", historyState.risk_level);
  if (historyState.defense_mode !== "all") params.set("defense_mode", historyState.defense_mode);
  params.set("sort_by", historyState.sort_by);
  params.set("sort_dir", historyState.sort_dir);
  params.set("page", historyState.page);
  params.set("page_size", historyState.page_size);
  return params.toString();
}

async function loadHistory() {
  const body = document.getElementById("historyBody");
  body.innerHTML = `<tr><td colspan="8"><div class="empty-state">Loading&hellip;</div></td></tr>`;
  updateSortArrows();

  try {
    const res = await fetch(`/api/history?${buildHistoryQuery()}`).then((r) => r.json());
    if (!res.success) throw new Error(res.error);
    historyRows = res.data || [];
    renderHistoryTable(historyRows);
    renderPagination(res.meta);
  } catch (e) {
    body.innerHTML = `<tr><td colspan="8"><div class="empty-state">Could not load history.</div></td></tr>`;
  }
}

function renderHistoryTable(rows) {
  const body = document.getElementById("historyBody");
  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="8"><div class="empty-state">No matching records.</div></td></tr>`;
    return;
  }
  body.innerHTML = rows.map((t) => `
    <tr data-id="${t.id}">
      <td>#${t.id}</td>
      <td>${psFormatTime(t.timestamp)}</td>
      <td>${psEscapeHtml(psFormatLabel(t.attack_type))}</td>
      <td>${psEscapeHtml(psFormatLabel(t.difficulty))}</td>
      <td><span class="severity-pill ${psSeverityClass(t.risk_level)}">${t.risk_score ?? "n/a"}</span></td>
      <td>${t.confidence != null ? Math.round(t.confidence * 100) + "%" : "n/a"}</td>
      <td>${psEscapeHtml(psFormatLabel(t.defense_mode))}</td>
      <td>${psEscapeHtml(psFormatLabel(t.final_decision))}</td>
    </tr>
  `).join("");

  body.querySelectorAll("tr[data-id]").forEach((tr) => {
    tr.addEventListener("click", () => {
      const test = historyRows.find((t) => String(t.id) === tr.dataset.id);
      if (test) window.PromptShieldUI.openTestModal(test);
    });
  });
}

function renderPagination(meta) {
  const info = document.getElementById("paginationInfo");
  const controls = document.getElementById("paginationControls");
  if (!meta) {
    info.textContent = "";
    controls.innerHTML = "";
    return;
  }

  const start = meta.total === 0 ? 0 : (meta.page - 1) * meta.page_size + 1;
  const end = Math.min(meta.total, meta.page * meta.page_size);
  info.textContent = `Showing ${start}\u2013${end} of ${meta.total}`;

  let html = `<button class="page-btn" id="prevPageBtn" ${meta.page <= 1 ? "disabled" : ""}><i data-lucide="chevron-left"></i></button>`;
  const maxButtons = 5;
  let startPage = Math.max(1, meta.page - Math.floor(maxButtons / 2));
  let endPage = Math.min(meta.pages, startPage + maxButtons - 1);
  startPage = Math.max(1, endPage - maxButtons + 1);

  for (let p = startPage; p <= endPage; p++) {
    html += `<button class="page-btn ${p === meta.page ? "is-active" : ""}" data-page="${p}">${p}</button>`;
  }
  html += `<button class="page-btn" id="nextPageBtn" ${meta.page >= meta.pages ? "disabled" : ""}><i data-lucide="chevron-right"></i></button>`;
  controls.innerHTML = html;

  const prev = document.getElementById("prevPageBtn");
  const next = document.getElementById("nextPageBtn");
  if (prev) prev.addEventListener("click", () => { historyState.page = Math.max(1, meta.page - 1); loadHistory(); });
  if (next) next.addEventListener("click", () => { historyState.page = Math.min(meta.pages, meta.page + 1); loadHistory(); });
  controls.querySelectorAll("[data-page]").forEach((btn) => {
    btn.addEventListener("click", () => { historyState.page = parseInt(btn.dataset.page, 10); loadHistory(); });
  });

  if (window.lucide) window.lucide.createIcons();
}

function updateSortArrows() {
  document.querySelectorAll("#historyTable th[data-sort]").forEach((th) => {
    const arrow = th.querySelector(".sort-arrow");
    if (!arrow) return;
    if (th.dataset.sort === historyState.sort_by) {
      arrow.textContent = historyState.sort_dir === "asc" ? "\u2191" : "\u2193";
    } else {
      arrow.textContent = "";
    }
  });
}
