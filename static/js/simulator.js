/**
 * PromptShield AI — Attack Simulator
 * Loads scenarios from /api/scenarios, groups them into Basic/Medium/
 * Advanced tabs by difficulty, and runs each through /api/simulate.
 */

let allScenarios = [];
let activeDifficulty = "all";

document.addEventListener("DOMContentLoaded", () => {
  loadScenarios();
  document.querySelectorAll("#difficultyTabs .tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll("#difficultyTabs .tab-btn").forEach((b) => b.classList.remove("is-active"));
      btn.classList.add("is-active");
      activeDifficulty = btn.dataset.difficulty;
      renderScenarios();
    });
  });
});

async function loadScenarios() {
  try {
    const res = await PromptShieldAPI.scenarios();
    allScenarios = res.data || [];
    renderScenarios();
  } catch (e) {
    document.getElementById("scenarioGrid").innerHTML =
      `<div class="empty-state"><i data-lucide="alert-triangle"></i><div>Could not load scenarios.</div></div>`;
    if (window.lucide) window.lucide.createIcons();
  }
}

function renderScenarios() {
  const grid = document.getElementById("scenarioGrid");
  const filtered = activeDifficulty === "all"
    ? allScenarios
    : allScenarios.filter((s) => s.difficulty === activeDifficulty);

  if (!filtered.length) {
    grid.innerHTML = `<div class="empty-state">No scenarios in this category.</div>`;
    return;
  }

  grid.innerHTML = filtered.map((s) => `
    <div class="glass-card scenario-card" data-scenario-id="${s.id}">
      <div class="scenario-card-header">
        <h4>${psEscapeHtml(s.name)}</h4>
        <span class="pill pill--violet">${psEscapeHtml(psFormatLabel(s.category))}</span>
      </div>
      <p class="sc-desc">${psEscapeHtml(s.description)}</p>
      <div class="scenario-meta">
        <span class="pill">${difficultyLabel(s.difficulty)}</span>
        <span class="severity-pill ${psSeverityClass(s.risk_level)}">${psEscapeHtml(s.risk_level)}</span>
      </div>
      <div class="scenario-detail-row"><strong>Expected Behavior:</strong> ${psEscapeHtml(s.expected_behavior || "n/a")}</div>
      <div class="scenario-detail-row"><strong>Defense Strategy:</strong> ${psEscapeHtml(s.defense_strategy || "n/a")}</div>
      <button class="btn btn-primary run-sim-btn" type="button">
        <i data-lucide="play"></i> RUN SIMULATION
      </button>
      <div class="scenario-result" id="simResult-${s.id}"></div>
    </div>
  `).join("");

  grid.querySelectorAll(".run-sim-btn").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const card = e.target.closest(".scenario-card");
      const id = parseInt(card.dataset.scenarioId, 10);
      const scenario = allScenarios.find((s) => s.id === id);
      if (scenario) runSimulation(scenario, btn);
    });
  });

  if (window.lucide) window.lucide.createIcons();
}

function difficultyLabel(d) {
  return { easy: "Basic", medium: "Medium", hard: "Advanced" }[d] || psFormatLabel(d);
}

async function runSimulation(scenario, btn) {
  const resultEl = document.getElementById(`simResult-${scenario.id}`);
  const defenseMode = document.getElementById("simDefenseMode").value;

  btn.disabled = true;
  btn.textContent = "RUNNING\u2026";
  resultEl.classList.add("is-visible");
  resultEl.innerHTML = `Running simulation against the security pipeline\u2026`;

  try {
    const res = await fetch("/api/simulate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        prompt: scenario.description,
        scenario_id: scenario.id,
        defense_mode: defenseMode,
      }),
    }).then((r) => r.json());

    if (!res.success) throw new Error(res.error || "Simulation failed.");
    const d = res.data;
    resultEl.innerHTML = `
      <div class="modal-grid" style="margin-bottom:8px;">
        <div class="modal-stat"><div class="ms-label">Risk Score</div><div class="ms-value">${d.risk_score} / 100</div></div>
        <div class="modal-stat"><div class="ms-label">Risk Level</div><div class="ms-value"><span class="severity-pill ${psSeverityClass(d.risk_level)}">${d.risk_level}</span></div></div>
        <div class="modal-stat"><div class="ms-label">Detected</div><div class="ms-value">${d.detected ? "Yes" : "No"}</div></div>
        <div class="modal-stat"><div class="ms-label">Final Decision</div><div class="ms-value">${psEscapeHtml(psFormatLabel(d.final_decision))}</div></div>
      </div>
      <div><strong>Model response:</strong> ${psEscapeHtml(d.model_response || "(blocked before reaching the model)")}</div>
    `;
  } catch (err) {
    resultEl.innerHTML = `<span style="color:var(--c-red)">${psEscapeHtml(err.message)}</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<i data-lucide="play"></i> RUN SIMULATION`;
    if (window.lucide) window.lucide.createIcons();
  }
}
