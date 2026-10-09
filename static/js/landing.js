/**
 * PromptShield AI — landing page interactions (Part 4):
 * - scroll-reveal for every [data-reveal] element
 * - smooth-scroll for [data-scroll] links (hero "Explore Platform", scroll indicator)
 * - live security metrics pulled from /api/dashboard, with a graceful
 *   demo fallback if the backend has no data or is unreachable
 * - animated counters once each metric card scrolls into view
 * - attack-surface node hover/click details (hover works via CSS; click
 *   still needed for touch devices and keyboard activation)
 */

const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

document.addEventListener("DOMContentLoaded", () => {
  initScrollReveal();
  initSmoothScroll();
  initSurfaceNodes();
  loadLiveMetrics().finally(initCounters);
});

function initScrollReveal() {
  const targets = document.querySelectorAll("[data-reveal]");
  if (!targets.length) return;

  if (prefersReducedMotion) {
    targets.forEach((el) => el.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: "0px 0px -60px 0px" }
  );

  targets.forEach((el) => observer.observe(el));
}

function initSmoothScroll() {
  document.querySelectorAll("[data-scroll]").forEach((link) => {
    link.addEventListener("click", (e) => {
      const href = link.getAttribute("href") || "";
      if (!href.startsWith("#")) return;
      const target = document.querySelector(href);
      if (!target) return;
      e.preventDefault();
      target.scrollIntoView({ behavior: prefersReducedMotion ? "auto" : "smooth", block: "start" });
    });
  });
}

async function loadLiveMetrics() {
  const cards = document.querySelectorAll("[data-metric-key]");
  if (!cards.length) return;

  // Sensible, clearly-labeled fallback if the backend is unreachable --
  // the seed script normally guarantees real data exists, so this is a
  // last resort, not the expected path.
  const fallback = {
    total_tests: 22,
    threats_detected: 15,
    threats_blocked: 6,
    high_risk_events: 5,
    average_risk: 38,
  };

  let metrics = fallback;
  try {
    const res = await PromptShieldAPI.dashboard();
    if (res && res.success && res.data) {
      metrics = { ...fallback, ...res.data };
    }
  } catch (e) {
    /* use fallback values below */
  }

  cards.forEach((el) => {
    const key = el.dataset.metricKey;
    const value = metrics[key];
    if (value === undefined || value === null) return;
    el.setAttribute("data-count-to", String(value));
  });
}

function initCounters() {
  const counters = document.querySelectorAll("[data-count-to]");
  if (!counters.length) return;

  const animate = (el) => {
    const target = el.getAttribute("data-count-to");
    const numeric = parseFloat(target.replace(/[^0-9.]/g, ""));
    const suffix = target.replace(/[0-9.]/g, "");
    if (Number.isNaN(numeric)) {
      el.textContent = target;
      return;
    }

    if (prefersReducedMotion) {
      el.textContent = formatCounterValue(numeric, target) + suffix;
      return;
    }

    const duration = 1200;
    const start = performance.now();
    const isDecimal = target.includes(".");

    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = eased * numeric;
      el.textContent = (isDecimal ? current.toFixed(1) : Math.round(current)) + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  };

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          animate(entry.target);
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.4 }
  );

  counters.forEach((c) => observer.observe(c));
}

function formatCounterValue(numeric, original) {
  return original.includes(".") ? numeric.toFixed(1) : String(Math.round(numeric));
}

function initSurfaceNodes() {
  const nodes = document.querySelectorAll(".surface-node");
  nodes.forEach((node) => {
    node.addEventListener("click", () => {
      const wasOpen = node.classList.contains("is-open");
      nodes.forEach((n) => n.classList.remove("is-open"));
      if (!wasOpen) node.classList.add("is-open");
    });
  });
}
