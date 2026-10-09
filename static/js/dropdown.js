/**
 * PromptShield AI — Custom Dropdown Component
 *
 * FIXES: native <select> option panels render with the browser's default
 * (usually white/light) styling regardless of how the closed select is
 * themed, because most browsers don't reliably honor CSS on <option>
 * elements. This replaces the *rendering* of every <select> on the page
 * with a fully themed, dark, accessible listbox -- while keeping the
 * original <select> in the DOM as the single source of truth for its
 * value, so no existing code has to change:
 *
 *   - `document.getElementById(id).value`      -> still works
 *   - `select.addEventListener("change", fn)`  -> still fires
 *   - forms/backends reading the select's value -> unaffected
 *   - options added dynamically after page load -> auto-detected and
 *     rebuilt (e.g. the Lab's scenario picker, populated from an API
 *     call after DOMContentLoaded)
 *
 * Keyboard: ArrowUp/ArrowDown to move, Home/End to jump, Enter/Space to
 * choose, Escape to close, click-outside to close. Falls back to the
 * (also dark-themed, see main.css) native <select> if JavaScript fails.
 */

(function () {
  "use strict";

  // Tracks the close() function of whichever custom dropdown is
  // currently open, so opening a new one properly closes the previous
  // one (removing ITS document-level listeners too) instead of just
  // toggling a CSS class and leaking that listener forever.
  let closeCurrentlyOpen = null;

  function enhanceSelect(select) {
    if (select.dataset.psEnhanced) return;
    if (select.closest(".ps-select")) return; // already inside a built wrapper
    select.dataset.psEnhanced = "true";

    const wrapper = document.createElement("div");
    wrapper.className = "ps-select";
    select.parentNode.insertBefore(wrapper, select);
    wrapper.appendChild(select);

    select.classList.add("ps-select-native");
    select.setAttribute("aria-hidden", "true");
    select.tabIndex = -1;

    const trigger = document.createElement("button");
    trigger.type = "button";
    trigger.className = "ps-select-trigger";
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");

    const triggerId = select.id ? select.id + "-trigger" : "";
    if (triggerId) trigger.id = triggerId;

    const labelEl = select.id ? document.querySelector(`label[for="${select.id}"]`) : null;
    if (labelEl) {
      if (!labelEl.id) labelEl.id = select.id + "-label";
      trigger.setAttribute("aria-labelledby", labelEl.id + (triggerId ? " " + triggerId : ""));
      // Clicking the original <label for="select-id"> would otherwise try
      // to focus the now-hidden native select; redirect it to the trigger.
      labelEl.addEventListener("click", (e) => {
        e.preventDefault();
        trigger.focus();
      });
    } else if (select.getAttribute("aria-label")) {
      trigger.setAttribute("aria-label", select.getAttribute("aria-label"));
    }

    const valueEl = document.createElement("span");
    valueEl.className = "ps-select-value";
    trigger.appendChild(valueEl);

    const chevron = document.createElement("span");
    chevron.className = "ps-select-chevron";
    chevron.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>';
    trigger.appendChild(chevron);

    const listbox = document.createElement("ul");
    listbox.className = "ps-select-listbox";
    listbox.setAttribute("role", "listbox");
    listbox.tabIndex = -1;
    if (select.id) {
      listbox.id = select.id + "-listbox";
      trigger.setAttribute("aria-controls", listbox.id);
    }

    wrapper.appendChild(trigger);
    wrapper.appendChild(listbox);

    let optionEls = [];
    let activeIndex = -1;

    function buildOptions() {
      listbox.innerHTML = "";
      optionEls = Array.from(select.options).map((opt, i) => {
        const li = document.createElement("li");
        li.className = "ps-select-option";
        li.setAttribute("role", "option");
        li.id = (select.id || "ps-select") + "-option-" + i;
        li.textContent = opt.textContent;
        if (opt.disabled) {
          li.classList.add("is-disabled");
          li.setAttribute("aria-disabled", "true");
        }
        li.addEventListener("click", () => {
          if (opt.disabled) return;
          selectIndex(i);
          closeList();
          trigger.focus();
        });
        listbox.appendChild(li);
        return li;
      });
      syncFromSelect();
    }

    function syncFromSelect() {
      const idx = select.selectedIndex;
      optionEls.forEach((li, i) => {
        const isSelected = i === idx;
        li.setAttribute("aria-selected", isSelected ? "true" : "false");
        li.classList.toggle("is-selected", isSelected);
      });
      valueEl.textContent = select.options[idx] ? select.options[idx].textContent : "";
      activeIndex = idx;
    }

    function selectIndex(i) {
      if (i < 0 || i >= select.options.length || select.options[i].disabled) return;
      const changed = select.selectedIndex !== i;
      select.selectedIndex = i;
      syncFromSelect();
      if (changed) select.dispatchEvent(new Event("change", { bubbles: true }));
    }

    function openList() {
      if (wrapper.classList.contains("is-open")) return;
      if (closeCurrentlyOpen) closeCurrentlyOpen();
      closeCurrentlyOpen = closeList;
      positionListbox();
      wrapper.classList.add("is-open");
      trigger.setAttribute("aria-expanded", "true");
      highlight(activeIndex >= 0 ? activeIndex : 0);
      document.addEventListener("mousedown", onDocMouseDown, true);
      document.addEventListener("keydown", onKeyDown);
      window.addEventListener("resize", positionListbox);
      window.addEventListener("scroll", positionListbox, true);
    }

    // Opens downward by default; flips upward when there isn't enough
    // room below the trigger but there is above, so the menu never gets
    // clipped by the viewport or overlaps the wrong direction.
    function positionListbox() {
      const triggerRect = trigger.getBoundingClientRect();
      const menuHeight = Math.min(260, listbox.scrollHeight || 260);
      const spaceBelow = window.innerHeight - triggerRect.bottom;
      const spaceAbove = triggerRect.top;
      const opensUp = spaceBelow < menuHeight + 12 && spaceAbove > spaceBelow;
      wrapper.classList.toggle("opens-up", opensUp);
    }

    function closeList() {
      wrapper.classList.remove("is-open");
      trigger.setAttribute("aria-expanded", "false");
      document.removeEventListener("mousedown", onDocMouseDown, true);
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", positionListbox);
      window.removeEventListener("scroll", positionListbox, true);
      if (closeCurrentlyOpen === closeList) closeCurrentlyOpen = null;
    }

    function toggleList() {
      if (wrapper.classList.contains("is-open")) closeList();
      else openList();
    }

    function highlight(i) {
      if (!optionEls.length) return;
      activeIndex = Math.max(0, Math.min(i, optionEls.length - 1));
      optionEls.forEach((li, idx) => li.classList.toggle("is-active", idx === activeIndex));
      const el = optionEls[activeIndex];
      if (el) {
        el.scrollIntoView({ block: "nearest" });
        trigger.setAttribute("aria-activedescendant", el.id);
      }
    }

    function onDocMouseDown(e) {
      if (!wrapper.contains(e.target)) closeList();
    }

    function onKeyDown(e) {
      if (!wrapper.classList.contains("is-open")) return;
      switch (e.key) {
        case "Escape":
          e.preventDefault();
          closeList();
          trigger.focus();
          break;
        case "ArrowDown":
          e.preventDefault();
          highlight(activeIndex + 1);
          break;
        case "ArrowUp":
          e.preventDefault();
          highlight(activeIndex - 1);
          break;
        case "Home":
          e.preventDefault();
          highlight(0);
          break;
        case "End":
          e.preventDefault();
          highlight(optionEls.length - 1);
          break;
        case "Enter":
        case " ":
          e.preventDefault();
          selectIndex(activeIndex);
          closeList();
          trigger.focus();
          break;
        case "Tab":
          closeList();
          break;
      }
    }

    trigger.addEventListener("click", toggleList);
    trigger.addEventListener("keydown", (e) => {
      if (wrapper.classList.contains("is-open")) return;
      if (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openList();
      }
    });

    // If something else changes the underlying select's value directly
    // (dispatching its own 'change'), keep the custom UI in sync.
    select.addEventListener("change", syncFromSelect);

    // The Lab's scenario picker appends <option> elements after an async
    // fetch; rebuild the custom listbox whenever the select's options change.
    const observer = new MutationObserver(buildOptions);
    observer.observe(select, { childList: true });

    buildOptions();
  }

  function enhanceAll(root) {
    (root || document).querySelectorAll("select").forEach(enhanceSelect);
  }

  document.addEventListener("DOMContentLoaded", () => enhanceAll(document));

  // Exposed so pages that inject new <select> elements after load (rare,
  // but future-proof) can call PSDropdown.enhanceAll() again safely --
  // already-enhanced selects are skipped via the `psEnhanced` flag.
  window.PSDropdown = { enhanceAll, enhanceSelect };
})();
