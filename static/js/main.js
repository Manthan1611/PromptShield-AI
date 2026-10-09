/**
 * PromptShield AI — shared site behavior (icons, mobile nav toggle,
 * shared detail modal, and small formatting helpers used across pages).
 */

document.addEventListener("DOMContentLoaded", () => {
  if (window.lucide) window.lucide.createIcons();

  const toggle = document.getElementById("navMenuToggle");
  const mobileMenu = document.getElementById("navLinksMobile");
  if (toggle && mobileMenu) {
    toggle.addEventListener("click", () => {
      const isOpen = mobileMenu.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(isOpen));
    });
  }

  wireDetailModal();

  // Quick backend reachability check (non-blocking, silent on failure)
  if (window.PromptShieldAPI) {
    PromptShieldAPI.health().catch(() => {
      /* backend not reachable yet — pages still render statically */
    });
  }
});

/* ---------------------------------------------------------------------- */
/* Shared detail modal — any page calls PromptShieldUI.openTestModal(test) */
/* ---------------------------------------------------------------------- */

function wireDetailModal() {
  const overlay = document.getElementById("detailModal");
  const closeBtn = document.getElementById("detailModalClose");
  if (!overlay) return;

  let lastFocused = null;

  const close = () => {
    overlay.classList.remove("is-open");
    overlay.setAttribute("aria-hidden", "true");
    if (lastFocused && typeof lastFocused.focus === "function") lastFocused.focus();
  };
  if (closeBtn) closeBtn.addEventListener("click", close);
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) close();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && overlay.classList.contains("is-open")) close();
  });

  window.PromptShieldUI = window.PromptShieldUI || {};
  window.PromptShieldUI._onModalOpen = () => {
    lastFocused = document.activeElement;
    if (closeBtn) closeBtn.focus();
  };
  window.PromptShieldUI._closeModal = close;
}

function psFormatLabel(value) {
  if (value === null || value === undefined || value === "") return "n/a";
  return String(value).replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function psSeverityClass(level) {
  const known = ["safe", "low", "medium", "high", "critical"];
  return known.includes(level) ? `sev-${level}` : "sev-low";
}

function psFormatTime(iso) {
  if (!iso) return "n/a";
  try {
    const d = new Date(iso);
    return d.toLocaleString(undefined, {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    });
  } catch (e) {
    return iso;
  }
}

function psEscapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

/**
 * Renders a SecurityTest record (as returned by /api/history or
 * /api/analyze) into the shared modal. `detectionResult` is the parsed
 * JSON from the test's detection_result field, if available.
 */
window.PromptShieldUI = {
  openTestModal(test) {
    const overlay = document.getElementById("detailModal");
    const content = document.getElementById("detailModalContent");
    if (!overlay || !content) return;

    let parsed = {};
    try {
      parsed = test.detection_result ? JSON.parse(test.detection_result) : {};
    } catch (e) {
      parsed = {};
    }

    const indicators = parsed.indicators || {};
    const recommendations = parsed.recommendations || [];
    const outputAnalysis = parsed.output_analysis;
    const blockedBy = parsed.blocked_by;

    const indicatorRows = Object.entries(indicators)
      .filter(([, v]) => v && v.score > 0)
      .map(([name, v]) => `<div class="modal-stat"><div class="ms-label">${psEscapeHtml(psFormatLabel(name))}</div><div class="ms-value">${v.score}</div></div>`)
      .join("") || `<div class="modal-stat"><div class="ms-label">Indicators</div><div class="ms-value">None triggered</div></div>`;

    const recoHtml = recommendations.length
      ? `<div class="modal-section"><div class="modal-section-title">Recommendations</div>${recommendations.map((r) => `<div class="reco-item">${psEscapeHtml(r)}</div>`).join("")}</div>`
      : "";

    const outputHtml = outputAnalysis ? `
      <div class="modal-section">
        <div class="modal-section-title">Output Analysis</div>
        <div class="modal-grid">
          <div class="modal-stat"><div class="ms-label">Safety Status</div><div class="ms-value">${psEscapeHtml(outputAnalysis.safety_status || "n/a")}</div></div>
          <div class="modal-stat"><div class="ms-label">Policy Compliance</div><div class="ms-value">${outputAnalysis.policy_compliance ? "Yes" : "No"}</div></div>
          <div class="modal-stat"><div class="ms-label">Info Leakage</div><div class="ms-value">${outputAnalysis.potential_information_leakage ? "Detected" : "None"}</div></div>
          <div class="modal-stat"><div class="ms-label">Tool Abuse Risk</div><div class="ms-value">${outputAnalysis.tool_abuse_risk ?? "n/a"}</div></div>
        </div>
      </div>` : "";

    content.innerHTML = `
      <div class="modal-title" id="detailModalTitle">Security Test #${test.id}</div>
      <div class="modal-subtitle">${psFormatTime(test.timestamp)} &middot; ${psEscapeHtml(psFormatLabel(test.defense_mode))} defense</div>

      <div class="modal-section">
        <div class="modal-section-title">Prompt</div>
        <div class="modal-prompt-block">${psEscapeHtml(test.prompt || "")}</div>
      </div>

      <div class="modal-section modal-grid">
        <div class="modal-stat"><div class="ms-label">Attack Type</div><div class="ms-value">${psEscapeHtml(psFormatLabel(test.attack_type))}</div></div>
        <div class="modal-stat"><div class="ms-label">Difficulty</div><div class="ms-value">${psEscapeHtml(psFormatLabel(test.difficulty))}</div></div>
        <div class="modal-stat"><div class="ms-label">Risk Score</div><div class="ms-value">${test.risk_score ?? "n/a"} / 100</div></div>
        <div class="modal-stat"><div class="ms-label">Risk Level</div><div class="ms-value"><span class="severity-pill ${psSeverityClass(test.risk_level)}">${psEscapeHtml(test.risk_level || "n/a")}</span></div></div>
        <div class="modal-stat"><div class="ms-label">Confidence</div><div class="ms-value">${test.confidence != null ? Math.round(test.confidence * 100) + "%" : "n/a"}</div></div>
        <div class="modal-stat"><div class="ms-label">Final Decision</div><div class="ms-value">${psEscapeHtml(psFormatLabel(test.final_decision))}</div></div>
      </div>

      ${blockedBy ? `<div class="modal-section"><div class="blocked-by-banner">Blocked by: ${psEscapeHtml(psFormatLabel(blockedBy))}</div></div>` : ""}

      <div class="modal-section">
        <div class="modal-section-title">Detection Indicators</div>
        <div class="modal-grid">${indicatorRows}</div>
      </div>

      ${outputHtml}
      ${recoHtml}
    `;

    overlay.classList.add("is-open");
    overlay.setAttribute("aria-hidden", "false");
    if (window.lucide) window.lucide.createIcons();
    if (typeof window.PromptShieldUI._onModalOpen === "function") {
      window.PromptShieldUI._onModalOpen();
    }
  },
};
