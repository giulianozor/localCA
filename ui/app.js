(() => {
  const langSelect = document.querySelector(".js-lang-select");
  if (langSelect && langSelect.form) {
    langSelect.addEventListener("change", () => {
      langSelect.form.submit();
    });
  }

  const deleteForms = document.querySelectorAll(".js-delete-cert-form");
  deleteForms.forEach((form) => {
    form.addEventListener("submit", (event) => {
      const confirmText = form.getAttribute("data-confirm-text");
      if (confirmText && !window.confirm(confirmText)) {
        event.preventDefault();
      }
    });
  });
})();
