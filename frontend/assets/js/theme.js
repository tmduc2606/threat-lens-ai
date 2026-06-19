(function () {
  function getPreferred() {
    var saved = localStorage.getItem("threatlens_theme");
    if (saved === "dark" || saved === "light") return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function apply(theme) {
    var html = document.documentElement;
    html.classList.remove("dark", "light");
    html.classList.add(theme);
    localStorage.setItem("threatlens_theme", theme);
    syncButtons(theme);
  }

  function syncButtons(theme) {
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      var isDark = theme === "dark";
      btn.textContent = isDark ? "\u2600\uFE0F Light" : "\uD83C\uDF19 Dark";
      btn.setAttribute("aria-label", "Switch to " + (isDark ? "light" : "dark") + " mode");
    });
  }

  function init() {
    var theme = getPreferred();
    apply(theme);

    document.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-theme-toggle]");
      if (!btn) return;
      var current = document.documentElement.classList.contains("dark") ? "dark" : "light";
      apply(current === "dark" ? "light" : "dark");
    });
  }

  window.ThreatLensTheme = { init: init, apply: apply, getPreferred: getPreferred };
})();
