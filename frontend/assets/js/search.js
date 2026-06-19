(function () {
  function doScan(query) {
    var params = new URLSearchParams(window.location.search);
    var currentQ = params.get("q");
    if (currentQ === query) return;

    params.set("q", query);
    var newUrl = window.location.pathname + "?" + params.toString();
    window.history.pushState({ q: query }, "", newUrl);

    // Trigger the SPA scan by dispatching a custom event
    var event = new CustomEvent("scan-requested", { detail: { query: query } });
    document.dispatchEvent(event);
  }

  function init() {
    // Event delegation for dynamically injected [data-rescan-query] buttons
    document.addEventListener("click", function (e) {
      var btn = e.target.closest("[data-rescan-query]");
      if (!btn) return;
      var query = btn.getAttribute("data-rescan-query") || "";
      if (!query) return;
      doScan(query);
    });
  }

  window.ThreatLensSearch = { init: init, doScan: doScan };
})();
