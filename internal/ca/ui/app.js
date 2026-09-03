(() => {
  // --- Certificate table filter (one per certificate-type tab) ---
  const setupCertFilter = (form) => {
    const input = form.querySelector(".js-cert-filter-input");
    const clearBtn = form.querySelector(".js-filter-clear");
    const card = form.closest(".card");
    const tableBody = card ? card.querySelector(".js-cert-table-body") : null;
    const certType = form.getAttribute("data-type") || "";
    if (!input || !tableBody) return;

    let filterTimeout = null;

    const refreshTable = async () => {
      try {
        const params = new URLSearchParams();
        const q = input.value.trim();
        if (q) params.set("q", q);
        if (certType) params.set("type", certType);
        const response = await window.fetch(`/certs/table?${params.toString()}`);
        if (!response.ok) {
          window.console.error(`Unable to refresh certificates table: HTTP ${response.status}`);
          return;
        }
        tableBody.innerHTML = await response.text();
      } catch (error) {
        window.console.error("Unable to refresh certificates table", error);
      }
    };

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      window.clearTimeout(filterTimeout);
      void refreshTable();
    });

    input.addEventListener("input", () => {
      window.clearTimeout(filterTimeout);
      filterTimeout = window.setTimeout(() => {
        void refreshTable();
      }, 300);
    });

    if (clearBtn) {
      const updateClearBtn = () => {
        clearBtn.classList.toggle("visible", input.value.length > 0);
      };
      input.addEventListener("input", updateClearBtn);
      clearBtn.addEventListener("click", () => {
        input.value = "";
        clearBtn.classList.remove("visible");
        window.clearTimeout(filterTimeout);
        void refreshTable();
        input.focus();
      });
      updateClearBtn();
    }

    input.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && input.value) {
        input.value = "";
        window.clearTimeout(filterTimeout);
        void refreshTable();
        e.preventDefault();
      }
    });
  };

  document.querySelectorAll(".js-cert-filter-form").forEach(setupCertFilter);

  // --- Tabbed navigation ---
  const tabButtons = document.querySelectorAll(".js-tab-btn");
  const tabPanels = document.querySelectorAll(".js-tab-panel");
  const VALID_TABS = ["ca", "server", "client", "dot1x", "code"];

  const selectTab = (name) => {
    if (!VALID_TABS.includes(name)) name = "ca";
    tabButtons.forEach((btn) => {
      const active = btn.getAttribute("data-tab") === name;
      btn.classList.toggle("active", active);
      btn.setAttribute("aria-selected", active ? "true" : "false");
    });
    tabPanels.forEach((panel) => {
      panel.hidden = panel.id !== "tab-" + name;
    });
    try {
      window.localStorage.setItem("localca-active-tab", name);
    } catch (_) { /* ignore */ }
    if (window.location.hash !== "#" + name) {
      window.history.replaceState(null, "", "#" + name);
    }
    const activeTabBtn = document.querySelector(`.js-tab-btn[data-tab="${name}"]`);
    if (activeTabBtn) activeTabBtn.focus();
  };

  if (tabButtons.length > 0) {
    tabButtons.forEach((btn) => {
      btn.addEventListener("click", () => selectTab(btn.getAttribute("data-tab")));
    });
    const initial = (window.location.hash || "").replace("#", "");
    const saved = (() => { try { return window.localStorage.getItem("localca-active-tab"); } catch (_) { return null; } })();
    const start = initial || saved || "ca";
    if (VALID_TABS.includes(start)) {
      selectTab(start);
    } else {
      selectTab("ca");
    }
  }

  // Keyboard arrow navigation across the tab bar
  const tabBar = document.querySelector(".js-tabs");
  if (tabBar) {
    tabBar.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
      const btns = Array.from(tabBar.querySelectorAll(".js-tab-btn"));
      const idx = btns.indexOf(document.activeElement);
      if (idx === -1) return;
      const next = e.key === "ArrowRight" ? (idx + 1) % btns.length : (idx - 1 + btns.length) % btns.length;
      btns[next].focus();
      e.preventDefault();
    });
  }

  // --- Language selector auto-submit ---
  const langSelect = document.querySelector(".js-lang-select");
  if (langSelect && langSelect.form) {
    langSelect.addEventListener("change", () => {
      langSelect.form.submit();
    });
  }

  // --- Confirm dialogs for destructive forms ---
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.classList.contains("js-delete-cert-form")) {
      return;
    }
    const confirmText = form.getAttribute("data-confirm-text");
    if (confirmText && !window.confirm(confirmText)) {
      event.preventDefault();
    }
  });

  // --- Loading state on form submissions ---
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.classList.contains("js-cert-filter-form")) return;
    if (form.classList.contains("js-no-loading")) return;

    const btn = form.querySelector('button[type="submit"]');
    if (btn && !btn.disabled) {
      btn.disabled = true;
      btn.dataset.originalText = btn.textContent;
      btn.innerHTML = '<span class="spinner"></span>' + btn.textContent;
    }
  });

  // --- Signer radio toggle for cert creation ---
  const signerRadios = document.querySelectorAll(".js-signer-radio");
  const signerPassWrap = document.querySelector(".js-signer-passphrase-wrap");
  const signerPassLabel = document.querySelector(".js-signer-passphrase-label");

  if (signerRadios.length > 0 && signerPassWrap) {
    const caLabel = signerPassLabel.textContent;

    const updatePassphraseField = () => {
      const selected = document.querySelector(".js-signer-radio:checked");
      if (!selected) return;
      const needsPassphrase = selected.getAttribute("data-passphrase") === "true";
      signerPassWrap.style.display = needsPassphrase ? "" : "none";
      if (selected.value === "intermediate") {
        signerPassLabel.textContent = "Intermediate key passphrase";
      } else {
        signerPassLabel.textContent = caLabel;
      }
    };

    signerRadios.forEach((r) => r.addEventListener("change", updatePassphraseField));
    updatePassphraseField();
  }

  // --- Reusable modal setup helper with focus management ---
  const setupModal = (overlaySelector, btnSelector, closeSelector, getData) => {
    const modal = document.querySelector(overlaySelector);
    if (!modal) return;
    let prevFocus = null;

    const getFocusable = () =>
      modal.querySelectorAll('button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"]):not([disabled])');

    const open = () => {
      prevFocus = document.activeElement;
      modal.classList.add("open");
      const first = getFocusable()[0];
      if (first) first.focus();
    };

    const close = () => {
      modal.classList.remove("open");
      if (prevFocus && prevFocus.focus) prevFocus.focus();
    };

    document.addEventListener("click", (e) => {
      const btn = e.target.closest(btnSelector);
      if (btn) {
        e.preventDefault();
        if (getData) getData(btn);
        open();
      }
    });

    modal.addEventListener("click", (e) => {
      if (e.target === modal) close();
    });

    document.querySelectorAll(closeSelector).forEach((el) => el.addEventListener("click", close));

    modal.addEventListener("keydown", (e) => {
      if (e.key === "Escape") { close(); return; }
      if (e.key !== "Tab") return;
      const focusable = getFocusable();
      if (focusable.length < 2) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });
  };

  setupModal(".js-passphrase-modal", ".js-passphrase-btn", ".js-modal-close",
    (btn) => { document.querySelector(".js-modal-cert-id").value = btn.getAttribute("data-cert-id"); });
  setupModal(".js-renew-modal", ".js-renew-btn", ".js-renew-close",
    (btn) => { document.querySelector(".js-renew-cert-id").value = btn.getAttribute("data-cert-id"); });
  setupModal(".js-export-modal", ".js-export-btn", ".js-export-close",
    (btn) => { document.querySelector(".js-export-cert-id").value = btn.getAttribute("data-cert-id"); });
  setupModal(".js-p12-modal", ".js-p12-btn", ".js-p12-close",
    (btn) => { document.querySelector(".js-p12-cert-id").value = btn.getAttribute("data-cert-id"); });
  setupModal(".js-ca-passphrase-modal", ".js-ca-passphrase-btn", ".js-ca-passphrase-close");
  setupModal(".js-ca-renew-modal", ".js-ca-renew-btn", ".js-ca-renew-close");
  setupModal(".js-crl-modal", ".js-crl-btn", ".js-crl-close");
  setupModal(".js-intermediate-passphrase-modal", ".js-intermediate-passphrase-btn", ".js-intermediate-passphrase-close");
  setupModal(".js-intermediate-renew-modal", ".js-intermediate-renew-btn", ".js-intermediate-renew-close");
  setupModal(".js-ca-export-modal", ".js-ca-export-btn", ".js-ca-export-close");
  setupModal(".js-ca-import-modal", ".js-ca-import-btn", ".js-ca-import-close");

  // --- Clean message/error query params to prevent re-display on refresh ---
  if (window.history.replaceState) {
    const url = new URL(window.location);
    if (url.searchParams.has("msg") || url.searchParams.has("err")) {
      url.searchParams.delete("msg");
      url.searchParams.delete("err");
      window.history.replaceState({}, "", url);
    }
  }

  // --- Auto-dismiss flash messages ---
  const autoDismiss = () => {
    const msgs = document.querySelectorAll(".msg, .err");
    msgs.forEach((el) => {
      setTimeout(() => {
        el.style.transition = "opacity 300ms ease, transform 300ms ease";
        el.style.opacity = "0";
        el.style.transform = "translateY(-8px)";
        setTimeout(() => el.remove(), 300);
      }, 5000);
    });
  };
  autoDismiss();
})();
