/**
 * PromptShield AI — Boot Intro sequencer.
 * Runs once per browser (localStorage flag), or every time if the user
 * navigates to /?intro=1 (used by the "Replay Intro" control in Settings).
 * Purely HTML/CSS/JS/SVG -- no images. Respects prefers-reduced-motion.
 */

(function () {
  "use strict";

  const overlay = document.getElementById("introOverlay");
  if (!overlay) return;

  const SKIP_KEY = "ps_skip_intro";
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const forceShow = new URLSearchParams(window.location.search).get("intro") === "1";
  const alreadySeen = localStorage.getItem(SKIP_KEY) === "true";

  if (alreadySeen && !forceShow) {
    overlay.remove();
    return;
  }

  const termBody = document.getElementById("introTermBody");
  const alertEl = document.getElementById("introAlert");
  const titleEl = document.getElementById("introTitle");
  const finalMsgEl = document.getElementById("introFinalMsg");
  const actionsEl = document.getElementById("introActions");
  const statusBarEl = document.getElementById("introStatusBar");
  const enterBtn = document.getElementById("introEnterBtn");
  const skipBtn = document.getElementById("introSkipBtn");

  let finished = false;
  const autoTimer = setTimeout(finishIntro, 6200);

  spawnParticles();
  if (skipBtn) skipBtn.addEventListener("click", finishIntro);
  if (enterBtn) enterBtn.addEventListener("click", finishIntro);
  document.addEventListener("keydown", onKeydownDuringIntro);

  if (prefersReducedMotion) {
    runReducedSequence().catch(() => finishIntro());
  } else {
    runFullSequence().catch(() => finishIntro());
  }

  // -------------------------------------------------------------------
  function spawnParticles() {
    const wrap = document.getElementById("introParticles");
    if (!wrap || prefersReducedMotion) return;
    const count = 16;
    for (let i = 0; i < count; i++) {
      const dot = document.createElement("span");
      dot.style.left = Math.random() * 100 + "%";
      dot.style.bottom = "0";
      dot.style.animationDuration = 6 + Math.random() * 6 + "s";
      dot.style.animationDelay = Math.random() * 6 + "s";
      wrap.appendChild(dot);
    }
  }

  function onKeydownDuringIntro(e) {
    if (e.key === "Escape") finishIntro();
  }

  function delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function appendLine(text, cls) {
    const line = document.createElement("div");
    line.className = "intro-line" + (cls ? " " + cls : "");
    line.textContent = text;
    termBody.appendChild(line);
    termBody.scrollTop = termBody.scrollHeight;
    return line;
  }

  async function typeLine(text, cls, speed) {
    const line = document.createElement("div");
    line.className = "intro-line" + (cls ? " " + cls : "");
    const cursor = document.createElement("span");
    cursor.className = "intro-cursor";
    termBody.appendChild(line);
    line.appendChild(document.createTextNode(""));
    line.appendChild(cursor);
    termBody.scrollTop = termBody.scrollHeight;

    for (let i = 0; i < text.length; i++) {
      line.firstChild.nodeValue += text[i];
      termBody.scrollTop = termBody.scrollHeight;
      await delay(speed);
    }
    cursor.remove();
    return line;
  }

  async function showOkBadges() {
    const modules = [
      "PROMPT ANALYZER", "THREAT DETECTOR", "RISK ENGINE",
      "DEFENSE ENGINE", "OUTPUT VALIDATOR", "AUDIT MONITOR",
    ];
    for (const m of modules) {
      const line = appendLine("", "is-ok");
      line.innerHTML = `<span class="ok-tag">[ OK ]</span> ${m}`;
      termBody.scrollTop = termBody.scrollHeight;
      await delay(65);
    }
  }

  async function showProgressBar() {
    const row = document.createElement("div");
    row.className = "intro-progress-row";
    row.innerHTML = `<span>[</span><span class="intro-progress-track"><span class="intro-progress-fill" id="introProgressFill"></span></span><span id="introProgressPct">0%</span>`;
    termBody.appendChild(row);
    termBody.scrollTop = termBody.scrollHeight;
    const fill = row.querySelector("#introProgressFill");
    const pct = row.querySelector("#introProgressPct");
    for (let p = 0; p <= 100; p += 20) {
      fill.style.width = p + "%";
      pct.textContent = p + "%";
      await delay(35);
    }
  }

  async function showAlert(text, cls) {
    alertEl.className = "intro-status-alert is-visible" + (cls ? " " + cls : "");
    alertEl.textContent = text;
    await delay(400);
  }

  function revealTitle() {
    titleEl.classList.add("is-visible");
  }

  function revealStatusBar() {
    statusBarEl.classList.add("is-visible");
  }

  async function revealFinalMessage() {
    finalMsgEl.classList.add("is-visible");
    finalMsgEl.textContent = "SECURITY SYSTEM READY";
    await delay(400);
    finalMsgEl.textContent = "WELCOME, OPERATOR.";
    await delay(250);
    actionsEl.classList.add("is-visible");
  }

  async function runFullSequence() {
    const bootLines = [
      "> initializing PromptShield security kernel...",
      "> loading threat detection engine...",
      "> loading prompt analyzer...",
      "> loading risk engine...",
      "> loading defense policies...",
      "> initializing AI simulation layer...",
      "> verifying security modules...",
      "> establishing isolated environment...",
    ];
    for (const l of bootLines) {
      await typeLine(l, null, 4);
      await delay(15);
    }

    await showOkBadges();
    await delay(100);

    await typeLine("> scanning attack surface...", null, 4);
    await showProgressBar();
    appendLine("SECURITY ENGINE INITIALIZED", "is-highlight");
    await delay(150);

    await typeLine("> ACCESSING SECURITY CORE...", null, 14);
    await delay(80);
    await typeLine("> AUTHENTICATING...", null, 14);
    await delay(80);
    await typeLine("> ACCESS GRANTED", "is-highlight", 14);
    await delay(100);
    await typeLine("> WELCOME TO PROMPTSHIELD AI", "is-highlight", 14);

    await showAlert("THREAT SURFACE: SCANNING...", "");
    await showAlert("THREATS: CONTAINED", "is-info");
    await showAlert("SYSTEM STATUS: SECURE", "is-safe");

    revealTitle();
    revealStatusBar();
    await delay(200);
    await revealFinalMessage();
  }

  async function runReducedSequence() {
    // Same information, no character-by-character typing or continuous
    // background motion -- simple fades only, finishes quickly.
    const bootLines = [
      "> initializing PromptShield security kernel...",
      "> loading threat detection engine...",
      "> loading prompt analyzer...",
      "> loading risk engine...",
      "> loading defense policies...",
      "> verifying security modules...",
    ];
    bootLines.forEach((l) => appendLine(l));
    await delay(120);
    await showOkBadges();
    appendLine("SECURITY ENGINE INITIALIZED", "is-highlight");
    await delay(120);
    appendLine("> ACCESS GRANTED", "is-highlight");
    appendLine("> WELCOME TO PROMPTSHIELD AI", "is-highlight");

    alertEl.className = "intro-status-alert is-visible is-safe";
    alertEl.textContent = "SYSTEM STATUS: SECURE";

    revealTitle();
    revealStatusBar();
    finalMsgEl.classList.add("is-visible");
    finalMsgEl.textContent = "WELCOME, OPERATOR.";
    actionsEl.classList.add("is-visible");
  }

  function finishIntro() {
    if (finished) return;
    finished = true;
    clearTimeout(autoTimer);
    document.removeEventListener("keydown", onKeydownDuringIntro);
    localStorage.setItem(SKIP_KEY, "true");

    // Strip the ?intro=1 replay param so a later refresh doesn't re-trigger it.
    if (forceShow && window.history && window.history.replaceState) {
      const url = new URL(window.location.href);
      url.searchParams.delete("intro");
      window.history.replaceState({}, "", url.toString());
    }

    overlay.classList.add("intro-exit");
    const exitDuration = prefersReducedMotion ? 450 : 950;
    setTimeout(() => overlay.remove(), exitDuration);
  }
})();
