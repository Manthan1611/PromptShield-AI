/**
 * PromptShield AI — API client
 * Thin wrapper around the fixed /api/* contract so every page (and
 * later parts) calls the backend the same way.
 */

const PromptShieldAPI = (() => {
  async function request(path, { method = "GET", body } = {}) {
    const opts = {
      method,
      headers: { "Content-Type": "application/json" },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);

    const res = await fetch(`/api${path}`, opts);
    let data;
    try {
      data = await res.json();
    } catch (e) {
      data = { success: false, error: "Invalid JSON response" };
    }
    if (!res.ok) {
      throw new Error(data.error || `Request to ${path} failed (${res.status})`);
    }
    return data;
  }

  return {
    health: () => request("/health"),
    analyze: (prompt) => request("/analyze", { method: "POST", body: { prompt } }),
    detect: (prompt) => request("/detect", { method: "POST", body: { prompt } }),
    simulate: (prompt, scenarioId) =>
      request("/simulate", { method: "POST", body: { prompt, scenario_id: scenarioId } }),
    defend: (riskLevel) => request("/defend", { method: "POST", body: { risk_level: riskLevel } }),
    dashboard: () => request("/dashboard"),
    analytics: () => request("/analytics"),
    history: () => request("/history"),
    events: () => request("/events"),
    scenarios: () => request("/scenarios"),
    saveSettings: (settings) => request("/settings", { method: "POST", body: settings }),
  };
})();
