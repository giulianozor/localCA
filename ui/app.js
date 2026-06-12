(() => {
  // --- Certificate table filter ---
  const certFilterForm = document.querySelector(".js-cert-filter-form");
  const certFilterInput = document.querySelector(".js-cert-filter-input");
  const certTableBody = document.querySelector(".js-cert-table-body");
  const certTableWrap = document.querySelector(".js-cert-table-wrap");

  if (certFilterForm && certFilterInput && certTableBody) {
    let filterTimeout = null;

    const refreshTable = async () => {
      try {
        const query = window.encodeURIComponent(certFilterInput.value);
        const response = await window.fetch(`/certs/table?q=${query}`);
        if (!response.ok) {
          window.console.error(`Unable to refresh certificates table: HTTP ${response.status}`);
          return;
        }
        certTableBody.innerHTML = await response.text();
      } catch (error) {
        window.console.error("Unable to refresh certificates table", error);
      }
    };

    certFilterForm.addEventListener("submit", (event) => {
      event.preventDefault();
      window.clearTimeout(filterTimeout);
      void refreshTable();
    });

    certFilterInput.addEventListener("input", () => {
      window.clearTimeout(filterTimeout);
      filterTimeout = window.setTimeout(() => {
        void refreshTable();
      }, 300);
    });

    // Add clear button behavior
    const clearBtn = document.querySelector(".js-filter-clear");
    if (clearBtn) {
      const updateClearBtn = () => {
        clearBtn.classList.toggle("visible", certFilterInput.value.length > 0);
      };
      certFilterInput.addEventListener("input", updateClearBtn);
      clearBtn.addEventListener("click", () => {
        certFilterInput.value = "";
        clearBtn.classList.remove("visible");
        window.clearTimeout(filterTimeout);
        void refreshTable();
        certFilterInput.focus();
      });
      updateClearBtn();
    }

    // Escape key clears filter
    certFilterInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && certFilterInput.value) {
        certFilterInput.value = "";
        window.clearTimeout(filterTimeout);
        void refreshTable();
        e.preventDefault();
      }
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
  setupModal(".js-ca-passphrase-modal", ".js-ca-passphrase-btn", ".js-ca-passphrase-close");
  setupModal(".js-ca-renew-modal", ".js-ca-renew-btn", ".js-ca-renew-close");
  setupModal(".js-crl-modal", ".js-crl-btn", ".js-crl-close");
  setupModal(".js-intermediate-passphrase-modal", ".js-intermediate-passphrase-btn", ".js-intermediate-passphrase-close");
  setupModal(".js-intermediate-renew-modal", ".js-intermediate-renew-btn", ".js-intermediate-renew-close");

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
