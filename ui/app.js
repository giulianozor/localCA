(() => {
  const certFilterForm = document.querySelector(".js-cert-filter-form");
  const certFilterInput = document.querySelector(".js-cert-filter-input");
  const certTableBody = document.querySelector(".js-cert-table-body");
  if (certFilterForm && certFilterInput && certTableBody) {
    let filterTimeout = null;
    const refreshTable = async () => {
      try {
        const params = new URLSearchParams({ q: certFilterInput.value });
        const response = await window.fetch(`/certs/table?${params.toString()}`);
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
  }

  const langSelect = document.querySelector(".js-lang-select");
  if (langSelect && langSelect.form) {
    langSelect.addEventListener("change", () => {
      langSelect.form.submit();
    });
  }

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
})();
