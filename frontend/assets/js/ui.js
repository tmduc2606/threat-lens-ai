(function () {
  function escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function sourceClass(sourceType) {
    var s = String(sourceType || "").toUpperCase();
    if (s === "CVE") return "bg-violet-600 text-slate-950";
    if (s === "DOMAIN") return "bg-cyan-600 text-slate-950";
    if (s === "IP") return "bg-amber-600 text-slate-950";
    if (s === "OTX") return "bg-emerald-600 text-slate-950";
    return "bg-slate-600 text-white";
  }

  function verdictPill(verdict) {
    var v = String(verdict || "UNKNOWN").toUpperCase();
    if (v === "MALICIOUS") return "bg-red-600 text-white";
    if (v === "SUSPICIOUS") return "bg-amber-600 text-slate-950";
    if (v === "CLEAN") return "bg-emerald-600 text-slate-950";
    return "bg-slate-600 text-white";
  }

  function inputTypeClass(inputType) {
    var s = String(inputType || "").toUpperCase();
    if (s === "CVE") return "bg-violet-600 text-slate-950";
    if (s === "DOMAIN") return "bg-cyan-600 text-slate-950";
    if (s === "IP") return "bg-amber-600 text-slate-950";
    if (s === "OTX") return "bg-emerald-600 text-slate-950";
    return "bg-slate-600 text-white";
  }

  function formatScore(score) {
    if (score === null || score === undefined || Number.isNaN(Number(score))) return "N/A";
    return Number(score).toFixed(1);
  }

  function scorePillClass(score) {
    if (score === null || score === undefined) return "bg-slate-800 text-slate-400";
    var s = Number(score);
    if (s >= 7.0) return "bg-red-600 text-white";
    if (s >= 4.0) return "bg-amber-600 text-slate-950";
    return "bg-emerald-600 text-slate-950";
  }

  function renderRecentScans(items) {
    var list = document.getElementById("recentScans");
    if (!list) return;

    var recent = items || JSON.parse(localStorage.getItem("threatlens_recent_scans") || "[]");

    if (!recent.length) {
      list.innerHTML = ""
        + '<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center text-sm text-slate-500">'
        + "No recent scans yet."
        + "</div>";
      return;
    }

    var html = recent.slice(0, 8).map(function (item) {
      return ""
        + '<button data-rescan-query="' + escapeHtml(item.query) + '"'
        + ' class="flex w-full items-center justify-between rounded-xl border border-slate-800 bg-slate-900 px-4 py-3 text-left transition hover:border-slate-700 hover:bg-slate-800/80">'
        + '<div class="min-w-0">'
        + '<div class="truncate text-sm font-medium text-white">' + escapeHtml(item.query) + "</div>"
        + '<div class="mt-0.5 flex flex-wrap items-center gap-1.5">'
        + '<span class="inline-block rounded-full px-2 py-0.5 text-xs ' + inputTypeClass(item.input_type) + '">' + escapeHtml(item.input_type || "?") + "</span>"
        + '<span class="inline-block rounded-full px-2 py-0.5 text-xs ' + verdictPill(item.verdict) + '">' + escapeHtml(item.verdict || "?") + "</span>"
        + "</div>"
        + "</div>"
        + '<div class="ml-3 text-xs text-slate-400">' + escapeHtml(item.confidence || "N/A") + "</div>"
        + "</button>";
    }).join("");

    html += ""
      + '<button id="clearHistoryBtn"'
      + ' class="w-full rounded-xl border border-dashed border-slate-700 bg-slate-900/50 px-4 py-2 text-xs text-slate-500 transition hover:border-red-800 hover:bg-red-950/30 hover:text-red-400">'
      + "Clear history"
      + "</button>";

    list.innerHTML = html;

    var clearBtn = document.getElementById("clearHistoryBtn");
    if (clearBtn) {
      clearBtn.addEventListener("click", function () {
        localStorage.removeItem("threatlens_recent_scans");
        renderRecentScans([]);
      });
    }
  }

  function saveRecentScan(scan) {
    var key = "threatlens_recent_scans";
    var current = JSON.parse(localStorage.getItem(key) || "[]");
    var next = [scan].concat(current.filter(function (item) { return item.query !== scan.query; })).slice(0, 10);
    localStorage.setItem(key, JSON.stringify(next));
  }

  function riskBandColor(band) {
    var b = String(band || "").toUpperCase();
    if (b === "CRITICAL") return "bg-red-500";
    if (b === "HIGH") return "bg-orange-500";
    if (b === "MEDIUM") return "bg-amber-500";
    if (b === "LOW") return "bg-slate-400";
    return "bg-slate-700";
  }

  function riskBandBadgeClass(band) {
    var b = String(band || "").toUpperCase();
    if (b === "CRITICAL") return "bg-red-600 text-white";
    if (b === "HIGH") return "bg-orange-600 text-white";
    if (b === "MEDIUM") return "bg-amber-600 text-slate-950";
    if (b === "LOW") return "bg-slate-600 text-white";
    return "bg-slate-700 text-slate-300";
  }

  function verdictBandClass(verdict) {
    var v = String(verdict || "UNKNOWN").toUpperCase();
    if (v === "MALICIOUS") return "bg-red-600";
    if (v === "SUSPICIOUS") return "bg-orange-500";
    if (v === "CLEAN") return "bg-emerald-600";
    return "bg-slate-700";
  }

  function verdictBandTextClass(verdict) {
    var v = String(verdict || "UNKNOWN").toUpperCase();
    if (v === "MEDIUM") return "text-slate-950";
    return "text-white";
  }

  function riskBandBgClass(band) {
    var b = String(band || "").toUpperCase();
    if (b === "CRITICAL") return "bg-red-600";
    if (b === "HIGH") return "bg-orange-500";
    if (b === "MEDIUM") return "bg-amber-500";
    if (b === "LOW") return "bg-slate-600";
    return "bg-slate-700";
  }

  function renderVerdictSummary(target, data) {
    if (!target) return;

    var detections = data.detections || {};
    var malicious = Number(detections.malicious || 0);
    var suspicious = Number(detections.suspicious || 0);
    var clean = Number(detections.clean || 0);
    var total = Number(data.engine_count || malicious + suspicious + clean || 0);
    var it = (data.input_type || "").toUpperCase();
    var isOtxCve = it === "OTX" || it === "CVE";
    var riskBand = data.risk_band || "";
    var calConf = data.calibrated_confidence;
    var ci = data.confidence_interval || {};
    var scoreVal = data.score;
    var bandColor = isOtxCve ? "bg-slate-700" : riskBand ? riskBandBgClass(riskBand) : verdictBandClass(data.verdict);
    var bandTextColor = isOtxCve ? "text-slate-300" : "text-white";

    target.innerHTML = ""
      + '<div class="rounded-2xl border border-slate-800 bg-slate-900/70 shadow-2xl shadow-black/20 animate-slideUp overflow-hidden">'
      + '<div class="' + bandColor + ' min-h-32 px-6 py-5">'
      + '<div class="flex flex-wrap items-end justify-between gap-4">'
      + '<div class="flex items-baseline gap-4">'
      + (isOtxCve
        ? '<span class="text-4xl font-black ' + bandTextColor + '">Reference record</span>'
        : '<span class="text-4xl font-black ' + bandTextColor + '">' + escapeHtml(data.verdict || "UNKNOWN") + "</span>")
      + (scoreVal !== null && scoreVal !== undefined && !isOtxCve
        ? '<span class="font-mono text-3xl ' + bandTextColor + ' opacity-80">' + formatScore(scoreVal) + "</span>"
        : "")
      + "</div>"
      + (riskBand && !isOtxCve
        ? '<span class="rounded-full px-3 py-1 text-xs font-semibold bg-black/30 ' + bandTextColor + '">' + escapeHtml(riskBand) + "</span>"
        : "")
      + (scoreVal !== null && scoreVal !== undefined && !isOtxCve
        ? '<span class="rounded-full px-3 py-1.5 text-xs font-semibold ' + scorePillClass(scoreVal) + '">Score ' + formatScore(scoreVal) + "</span>"
        : "")
      + "</div>"
      + (calConf !== null && calConf !== undefined && !isOtxCve
        ? '<div class="mt-4">'
        + '<div class="h-3 w-full rounded-full bg-black/30">'
        + '<div class="h-3 rounded-full bg-white/80 transition-all duration-600 ease-out" style="width: 0%" data-conf-width="' + calConf + '"></div>'
        + "</div>"
        + '<div class="mt-1 flex items-center justify-between text-xs text-white/90">'
        + '<span>' + calConf + '% confident</span>'
        + (ci.low !== undefined && ci.high !== undefined
          ? '<span>CI: ' + ci.low + '\u2013' + ci.high + '%</span>'
          : "")
        + "</div>"
        + "</div>"
        : "")
      + ((calConf === null || calConf === undefined) && !isOtxCve
        ? '<div class="mt-4">'
        + '<div class="flex items-center gap-2 text-xs text-white/50">'
        + '<span>Confidence: </span>'
        + '<span class="rounded-full bg-black/30 px-2 py-0.5">' + escapeHtml(data.confidence || "N/A") + '</span>'
        + '</div>'
        + '</div>'
        : "")
      + "</div>"
      + '<div class="px-6 py-5">'
      + '<h2 class="font-mono text-lg text-slate-200 select-all scroll-mt-20">' + escapeHtml(data.title || data.source_key || data.query) + "</h2>"
      + '<p class="mt-2 max-w-2xl text-sm text-slate-400">' + escapeHtml(data.summary || "No summary available.") + "</p>"
      + (!isOtxCve && total > 0
        ? '<div class="mt-5 grid gap-3 sm:grid-cols-3">'
        + '<div class="rounded-xl bg-red-950/30 p-4">'
        + '<div class="text-xs uppercase tracking-wide text-slate-300">Malicious</div>'
        + '<div class="mt-1 text-2xl font-semibold font-mono text-white">' + malicious + "</div>"
        + "</div>"
        + '<div class="rounded-xl bg-amber-950/30 p-4">'
        + '<div class="text-xs uppercase tracking-wide text-slate-300">Suspicious</div>'
        + '<div class="mt-1 text-2xl font-semibold font-mono text-white">' + suspicious + "</div>"
        + "</div>"
        + '<div class="rounded-xl bg-emerald-950/30 p-4">'
        + '<div class="text-xs uppercase tracking-wide text-slate-300">Clean</div>'
        + '<div class="mt-1 text-2xl font-semibold font-mono text-white">' + clean + "</div>"
        + "</div>"
        + "</div>"
        : '<div class="mt-5 text-sm text-slate-400">Reference record — no engine verdicts.</div>')
      + '<div class="mt-5 text-sm text-slate-500">'
      + '<span class="font-semibold text-slate-300">' + total + "</span> sources analyzed"
      + "</div>"
      + "</div>"
      + "</div>";
  }

  function sourceBorderClass(stype) {
    var s = String(stype || "").toUpperCase();
    if (s === "ML_PREDICTION") return "border-l-violet-500 border-slate-800/50";
    if (s === "API") return "border-l-cyan-500 border-slate-800/50";
    if (s === "HEURISTIC") return "border-l-amber-500 border-slate-800/50";
    if (s === "NETWORK") return "border-l-emerald-500 border-slate-800/50";
    return "border-l-slate-700 border-slate-800/50";
  }

  function sourceScoreBarColor(stype) {
    var s = String(stype || "").toUpperCase();
    if (s === "ML_PREDICTION") return "bg-violet-500";
    if (s === "API") return "bg-cyan-500";
    if (s === "HEURISTIC") return "bg-amber-500";
    if (s === "NETWORK") return "bg-emerald-500";
    return "bg-cyan-500";
  }

  function sourceTypeIcon(stype) {
    var s = String(stype || "").toUpperCase();
    if (s === "ML_PREDICTION") return "🧠";
    if (s === "API") return "🔌";
    if (s === "HEURISTIC") return "⚙️";
    if (s === "NETWORK") return "🌐";
    return "";
  }

  function renderSourceBreakdown(target, data) {
    if (!target) return;

    var sources = data.source_breakdown || [];
    if (!sources.length) {
      target.innerHTML = ""
        + '<div class="rounded-2xl border border-dashed border-slate-700 bg-slate-900/50 p-6 text-sm text-slate-500">'
        + "No source breakdown available."
        + "</div>";
      return;
    }

    var mlItems = [];
    var apiItems = [];
    var otherItems = [];

    sources.forEach(function (item) {
      var st = (item.source_type || "").toUpperCase();
      if (st === "ML_PREDICTION") { mlItems.push(item); }
      else if (st === "API" || st === "ABUSEIPDB" || st === "VIRUSTOTAL" || st === "NVD" || st === "OTX") { apiItems.push(item); }
      else { otherItems.push(item); }
    });

    var mlHtml = mlItems.map(function (item) { return renderMlCard(item); }).join("");
    var apiHtml = apiItems.map(renderSourceCard).join("");
    var otherHtml = otherItems.map(renderSourceCard).join("");

    target.innerHTML = ""
      + (mlHtml ? '<div class="animate-slideUp">' + mlHtml + "</div>" : "")
      + (apiHtml ? '<div class="mt-3 grid gap-3 items-stretch ' + (apiItems.length === 1 ? 'grid-cols-1' : apiItems.length === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3') + ' animate-slideUp stagger-1">' + apiHtml + "</div>" : "")
      + (otherHtml ? '<div class="mt-3 grid gap-3 items-stretch ' + (otherItems.length === 1 ? 'grid-cols-1' : otherItems.length === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-2 lg:grid-cols-3') + ' animate-slideUp stagger-2">' + otherHtml + "</div>" : "");

    if (!mlHtml && !apiHtml && !otherHtml) {
      target.innerHTML = '<div class="text-sm text-slate-500">No source breakdown available.</div>';
    }
  }

  function renderSourceCard(item) {
    var st = String(item.source_type || "").toUpperCase();
    var isOtxCve = st === "OTX" || st === "CVE";
    var scoreVal = Number(item.score);
    var scoreBarPct = scoreVal >= 0 && scoreVal <= 10 ? Math.round(scoreVal / 10 * 100) : 0;
    var bgTint = st === "ML_PREDICTION" ? "bg-violet-500/10" : st === "API" ? "bg-cyan-500/10" : st === "HEURISTIC" ? "bg-amber-500/10" : st === "NETWORK" ? "bg-emerald-500/10" : "bg-slate-900";

    return ""
      + '<div class="rounded-2xl border-l-4 overflow-hidden ' + sourceBorderClass(st) + ' ' + bgTint + ' p-5 ring-1 ring-slate-800/30">'
      + '<div class="flex items-start justify-between gap-3 flex-wrap">'
      + '<div class="flex items-center gap-2 min-w-0">'
      + '<span class="text-sm">' + sourceTypeIcon(st) + "</span>"
      + '<div class="min-w-0">'
      + '<div class="text-sm font-semibold text-white truncate">' + escapeHtml(item.source_type || "UNKNOWN") + "</div>"
      + '<div class="mt-0.5 text-xs text-slate-500 truncate">' + escapeHtml(item.engine || item.vendor || "Dataset model") + "</div>"
      + "</div>"
      + "</div>"
      + (isOtxCve
        ? '<span class="shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold bg-slate-700 text-slate-300">Reference</span>'
        : '<span class="shrink-0 rounded-full px-2.5 py-0.5 text-xs font-semibold ' + verdictPill(item.verdict) + '">' + escapeHtml(item.verdict || "UNKNOWN") + "</span>")
      + "</div>"
      + '<div class="mt-4 text-sm text-slate-300 line-clamp-3" title="' + escapeHtml(item.note || item.summary || "No signal available.") + '">' + escapeHtml(item.note || item.summary || "No signal available.") + "</div>"
      + '<div class="mt-4">'
      + '<div class="flex items-center gap-2 text-xs text-slate-500">'
      + '<span class="text-slate-400">Score</span>'
      + '<div class="flex-1 rounded-full bg-slate-800/70 h-3">'
      + '<div class="h-3 rounded-full ' + sourceScoreBarColor(st) + ' transition-all" style="width: ' + scoreBarPct + '%"></div>'
      + "</div>"
      + '<span class="w-8 text-right font-mono text-slate-300">' + formatScore(scoreVal) + "</span>"
      + "</div>"
      + "</div>"
      + '<div class="mt-4 pt-3 border-t border-slate-800/50 text-xs text-slate-500">'
      + "Confidence " + escapeHtml(item.confidence || "N/A")
      + "</div>"
      + "</div>";
  }

  function renderMlCard(item) {
    var mlConf = item.ml_confidence;
    var mlProbs = item.ml_probabilities || [];
    var mlClasses = item.ml_classes || [];
    var hasProbs = mlProbs.length > 0 && mlClasses.length > 0;
    var isUnavailable = item.prediction_source === "ml_unavailable" || item.verdict === "N/A";
    var st = "ML_PREDICTION";

    var probBars = "";
    if (hasProbs) {
      probBars = mlClasses.map(function (cls, i) {
        var pct = mlProbs[i];
        var barPct = Math.round(pct * 100);
        return '<div class="flex items-center gap-2 text-xs">'
          + '<span class="w-20 text-right text-slate-400">' + escapeHtml(String(cls)) + "</span>"
          + '<div class="flex-1 rounded-full bg-slate-800 h-4">'
          + '<div class="h-4 rounded-full bg-violet-500 transition-all" style="width: ' + barPct + '%"></div>'
          + "</div>"
          + '<span class="w-12 font-mono text-slate-300">' + barPct + '%</span>'
          + "</div>";
      }).join("");
    }

    var f1Note = item.ml_f1_score ? "F1=" + item.ml_f1_score : "";
    var sampleNote = item.ml_training_samples ? item.ml_training_samples + " samples" : "";
    var trainingNote = [f1Note, sampleNote].filter(Boolean).join(", ");

    return ""
      + '<div class="rounded-2xl border-l-4 overflow-hidden ' + sourceBorderClass(st) + ' bg-violet-500/5 p-5 ring-1 ring-slate-800/30">'
      + '<div class="flex items-start justify-between gap-3 flex-wrap">'
      + '<div class="min-w-0">'
      + '<div class="flex items-center gap-2">'
      + '<span class="text-sm">🧠</span>'
      + '<span class="text-sm font-semibold text-white">ML Prediction</span>'
      + (isUnavailable
        ? '<span class="shrink-0 rounded bg-slate-600/30 px-2 py-0.5 text-xs text-slate-400">ML N/A</span>'
        : '<span class="shrink-0 rounded bg-violet-500/10 px-2 py-0.5 text-xs text-violet-300">' + escapeHtml(item.engine || "") + "</span>")
      + "</div>"
      + '<div class="mt-1 text-xs text-slate-500 truncate">' + escapeHtml(item.summary || "") + "</div>"
      + "</div>"
      + (isUnavailable
        ? '<span class="shrink-0 rounded-full px-3 py-1 text-xs font-semibold bg-slate-700 text-slate-400">N/A</span>'
        : '<span class="shrink-0 rounded-full px-3 py-1 text-xs font-semibold ' + verdictPill(item.verdict) + '">' + escapeHtml(item.verdict || "UNKNOWN") + "</span>")
      + "</div>"
      + (isUnavailable
        ? '<div class="mt-4 rounded-lg bg-amber-500/10 border border-amber-500/20 px-3 py-2 text-xs text-amber-300">ML prediction unavailable — heuristic-only analysis. Models trained on real API data cannot reliably score synthetic features.</div>'
        : "")
      + (!isUnavailable && item.ml_confidence !== null && item.ml_confidence !== undefined
        ? '<div class="mt-4">'
        + '<div class="flex items-center justify-between text-xs text-slate-400 mb-1">'
        + '<span>Confidence</span>'
        + '<span>' + Math.round(item.ml_confidence * 100) + '%</span>'
        + "</div>"
        + '<div class="h-2 w-full rounded-full bg-slate-700">'
        + '<div class="h-2 rounded-full bg-violet-500 transition-all" style="width: ' + Math.round(item.ml_confidence * 100) + '%"></div>'
        + "</div>"
        + "</div>"
        : "")
      + (probBars
        ? '<div class="mt-4 space-y-1.5">'
        + '<div class="text-xs font-semibold text-slate-400">Per-class probabilities</div>'
        + probBars
        + "</div>"
        : "")
      + (trainingNote
        ? '<div class="mt-4 pt-3 border-t border-violet-500/10 text-xs text-slate-500">' + escapeHtml(trainingNote) + "</div>"
        : "")
      + "</div>";
  }

  function renderSourcesConsulted(sourceBreakdown) {
    var container = document.getElementById("sourcesConsulted");
    if (!container) return;

    var sources = sourceBreakdown || [];
    if (!sources.length) {
      container.innerHTML = "";
      return;
    }

    var items = sources.map(function (s) {
      var st = String(s.source_type || "").toUpperCase();
      if (st === "ML_PREDICTION") return null;
      var hasVerdict = s.verdict && s.verdict !== "UNKNOWN";
      var isError = s.error || false;
      var icon = isError ? "❌" : hasVerdict ? "✅" : "⚠️";
      return '<span class="text-xs text-slate-400">' + escapeHtml(s.source_type || "?") + "(" + icon + ")</span>";
    }).filter(Boolean).join("");

    var numSources = items.split("</span>").length - 1;
    container.innerHTML = items
      ? '<div class="flex flex-wrap gap-2 text-xs text-slate-500">' + numSources + ' sources: ' + items + "</div>"
      : "";
  }

  function renderTags(target, tags) {
    if (!target) return;
    var list = tags || [];
    target.innerHTML = list.length
      ? list.map(function (tag) {
        return '<span class="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">' + escapeHtml(tag) + "</span>";
      }).join("")
      : '<span class="text-sm text-slate-500">No tags.</span>';
  }

  function evidenceBorderClass(etype) {
    var t = String(etype || "").toLowerCase();
    if (t === "api") return "border-cyan-500/30";
    if (t === "ml") return "border-violet-500/30";
    if (t === "heuristic") return "border-amber-500/30";
    if (t === "network") return "border-emerald-500/30";
    return "border-slate-700";
  }

  function evidenceBadge(etype) {
    var t = String(etype || "").toLowerCase();
    if (t === "api") return '<span class="rounded bg-cyan-500/10 px-1.5 py-0.5 text-xs text-cyan-300">API</span>';
    if (t === "ml") return '<span class="rounded bg-violet-500/10 px-1.5 py-0.5 text-xs text-violet-300">ML</span>';
    if (t === "heuristic") return '<span class="rounded bg-amber-500/10 px-1.5 py-0.5 text-xs text-amber-300">Heuristic</span>';
    if (t === "network") return '<span class="rounded bg-emerald-500/10 px-1.5 py-0.5 text-xs text-emerald-300">Network</span>';
    return "";
  }

  function renderEvidence(target, evidence) {
    if (!target) return;
    var list = evidence || [];
    if (!list.length) {
      target.innerHTML = '<li class="text-sm text-slate-500">No explainability notes available.</li>';
      return;
    }

    var groups = { api: [], ml: [], heuristic: [], network: [] };
    list.forEach(function (item) {
      var text = typeof item === "string" ? item : (item.text || "");
      var etype = typeof item === "string" ? "heuristic" : (item.type || "heuristic");
      var key = etype.toLowerCase();
      if (!groups[key]) groups[key] = [];
      groups[key].push(text);
    });

    var typeLabels = { api: "API Evidence", ml: "ML Model Evidence", heuristic: "Heuristic Evidence", network: "Network Evidence" };
    var typeColors = { api: "border-cyan-500/20 bg-cyan-500/10", ml: "border-violet-500/20 bg-violet-500/10", heuristic: "border-amber-500/20 bg-amber-500/10", network: "border-emerald-500/20 bg-emerald-500/10" };
    var typeHeaderColors = { api: "text-cyan-400 border-cyan-500/20", ml: "text-violet-400 border-violet-500/20", heuristic: "text-amber-400 border-amber-500/20", network: "text-emerald-400 border-emerald-500/20" };
    var typeBadgeFn = { api: function () { return evidenceBadge("api"); }, ml: function () { return evidenceBadge("ml"); }, heuristic: function () { return evidenceBadge("heuristic"); }, network: function () { return evidenceBadge("network"); } };

    var html = "";
    Object.keys(groups).forEach(function (key) {
      var items = groups[key];
      if (!items.length) return;
      html += '<div class="rounded-xl border ' + typeColors[key] + ' p-3">'
        + '<div class="flex items-center gap-2 border-b ' + typeHeaderColors[key] + ' pb-2 mb-2">'
        + typeBadgeFn[key]()
        + '<span class="text-xs font-semibold ' + typeHeaderColors[key].split(" ")[0] + '">' + typeLabels[key] + ' (' + items.length + ')</span>'
        + "</div>"
        + items.map(function (text) {
          return '<div class="flex items-start gap-2 py-1.5 text-sm text-slate-300">'
            + '<span>' + escapeHtml(text) + "</span>"
            + "</div>";
        }).join("")
        + "</div>";
    });

    target.innerHTML = html || '<li class="text-sm text-slate-500">No explainability notes available.</li>';
  }

  function renderTipOfTheDay() {
    var container = document.getElementById("tipOfTheDayContent");
    if (!container) return;

    window.ThreatLensAPI.get("/tip-of-the-day").then(function (data) {
      container.innerHTML = ""
        + '<div class="rounded-xl border border-slate-800 bg-slate-900/60 p-4 tip-card">'
        + '<div class="flex items-start gap-3">'
        + '<span class="mt-0.5 shrink-0 text-sm text-cyan-400">💡</span>'
        + '<p class="text-xs leading-relaxed text-slate-400">' + escapeHtml(data.tip || "") + "</p>"
        + "</div>"
        + "</div>";
    }).catch(function () {
      container.innerHTML = "";
    });
  }

  function renderShapPanel(target, shapValues) {
    if (!target) return;
    var list = shapValues || [];
    if (!list.length) {
      target.innerHTML = '<div class="text-sm text-slate-500">No SHAP explanations available.</div>';
      return;
    }

    var maxImpact = Math.max.apply(null, list.map(function (s) { return Math.abs(s.impact || 0); }));

    target.innerHTML = ""
      + '<div class="rounded-xl border border-slate-800 bg-slate-900 p-4">'
      + '<h3 class="text-sm font-semibold text-slate-400">Why this verdict?</h3>'
      + '<div class="mt-4 space-y-2">'
      + list.slice(0, 10).map(function (s) {
        var impact = s.impact || 0;
        var barPct = maxImpact > 0 ? Math.round(Math.abs(impact) / maxImpact * 100) : 0;
        var barColor = impact >= 0 ? "bg-cyan-500" : "bg-red-500";
        return '<div class="flex items-center gap-3">'
          + '<span class="w-40 truncate text-right text-xs text-slate-400">' + escapeHtml(s.feature || "") + "</span>"
          + '<div class="flex-1 rounded-full bg-slate-800 h-5">'
          + '<div class="h-5 rounded-full ' + barColor + ' transition-all" style="width: ' + barPct + '%"></div>'
          + "</div>"
          + '<span class="w-16 text-xs font-mono text-slate-300">' + (impact >= 0 ? "+" : "") + impact.toFixed(3) + "</span>"
          + "</div>";
      }).join("")
      + "</div>"
      + "</div>";
  }

  function renderModelHealthBar(modelStatus) {
    var container = document.getElementById("modelHealthBar");
    if (!container) return;
    var status = modelStatus || {};

    var keys = Object.keys(status).filter(function (k) { return k !== "nmap_model" && k !== "otx_label_encoder"; });
    if (!keys.length) {
      container.innerHTML = ""
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 shadow-glow">'
        + '<div class="flex items-center gap-2">'
        + '<span class="text-sm">🧠</span>'
        + '<span class="text-sm font-semibold text-slate-300">Model Health</span>'
        + '<span class="ml-auto rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-400">No models loaded</span>'
        + "</div>"
        + '<div class="mt-2 text-xs text-slate-500">No .joblib models found in the models directory. ML predictions will be skipped.</div>'
        + "</div>";
      return;
    }

    function f1Color(f1) {
      if (f1 === null || f1 === undefined) return "text-slate-400";
      if (f1 >= 0.80) return "text-emerald-400";
      if (f1 >= 0.50) return "text-amber-400";
      return "text-red-400";
    }

    function f1Indicator(f1) {
      if (f1 === null || f1 === undefined) return "bg-slate-500";
      if (f1 >= 0.80) return "bg-emerald-500";
      if (f1 >= 0.50) return "bg-amber-500";
      return "bg-red-500";
    }

    var loadedCount = keys.filter(function (k) { var info = status[k] || {}; return info.loaded; }).length;
    var totalModels = keys.length;
    var healthPct = totalModels > 0 ? Math.round(loadedCount / totalModels * 100) : 0;
    var healthColor = healthPct >= 80 ? "text-emerald-400" : healthPct >= 50 ? "text-amber-400" : "text-red-400";

    var items = keys.map(function (k) {
      var info = status[k] || {};
      var loaded = info.loaded;
      var f1 = info.f1_score;
      var icon = loaded ? "✅" : "❌";
      var labelParts = [];
      if (loaded) {
        labelParts.push(escapeHtml(k));
        if (f1 !== null && f1 !== undefined) labelParts.push("F1=" + f1);
      } else {
        labelParts.push(escapeHtml(k) + " (off)");
      }
      return '<span class="inline-flex items-center gap-1.5 text-xs ' + f1Color(f1) + '">'
        + '<span class="inline-block h-1.5 w-1.5 rounded-full ' + f1Indicator(f1) + '"></span>'
        + icon + " " + labelParts.join(" ")
        + "</span>";
    });

    container.innerHTML = ""
      + '<div class="rounded-2xl border border-slate-800 bg-slate-900/70 p-4 shadow-glow">'
      + '<div class="flex items-center justify-between gap-3">'
      + '<div class="flex items-center gap-2">'
      + '<span class="text-sm">🧠</span>'
      + '<span class="text-sm font-semibold text-slate-300">Model Health</span>'
      + '<span class="text-xs ' + healthColor + '">(' + loadedCount + '/' + totalModels + ' active)</span>'
      + "</div>"
      + '<button id="modelHealthToggle" class="rounded-lg border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-400 hover:bg-slate-700">Details</button>'
      + "</div>"
      + '<div class="mt-3 flex flex-wrap gap-x-4 gap-y-1.5">'
      + items.join("")
      + "</div>"
      + '<div id="modelHealthDetails" class="mt-3 hidden border-t border-slate-800 pt-3 space-y-2"></div>'
      + "</div>";

    var toggle = document.getElementById("modelHealthToggle");
    var details = document.getElementById("modelHealthDetails");
    if (toggle && details) {
      toggle.addEventListener("click", function () {
        var hidden = details.classList.toggle("hidden");
        toggle.textContent = hidden ? "Details" : "Hide";
        if (!hidden) {
          details.innerHTML = keys.map(function (k) {
            var info = status[k] || {};
            var f1 = info.f1_score;
            var f1Class = f1Color(f1);
            return '<div class="flex items-center justify-between rounded-xl bg-slate-800/50 px-3 py-2 text-xs">'
              + '<span class="font-medium text-slate-300">' + escapeHtml(k) + "</span>"
              + '<div class="flex items-center gap-3 text-slate-400">'
              + '<span>Loaded: ' + (info.loaded ? "✅" : "❌") + "</span>"
              + (info.f1_score !== undefined ? '<span class="' + f1Class + '">F1: ' + info.f1_score + "</span>" : "")
              + (info.samples ? "<span>Samples: " + info.samples + "</span>" : "")
              + (info.trained_at ? "<span>Trained: " + info.trained_at + "</span>" : "")
              + "</div>"
              + "</div>";
          }).join("");
        }
      });
    }
  }

  function downloadScanCsv(scan) {
    var rows = [];
    var header = ["Field", "Value"];
    rows.push(header);

    function addRow(field, value) {
      rows.push([field, String(value ?? "")]);
    }

    addRow("Query", scan.query);
    addRow("Input Type", scan.input_type);
    addRow("Verdict", scan.verdict);
    addRow("Confidence Text", scan.confidence);
    addRow("Calibrated Confidence", scan.calibrated_confidence);
    addRow("Risk Band", scan.risk_band);
    addRow("Score", scan.score);
    var d = scan.detections || {};
    addRow("Malicious", d.malicious);
    addRow("Suspicious", d.suspicious);
    addRow("Clean", d.clean);
    addRow("Total Sources", scan.engine_count || d.total);
    addRow("Summary", scan.summary || "");

    var evidence = scan.evidence || [];
    evidence.forEach(function (e, i) {
      var text = typeof e === "string" ? e : (e.text || "");
      var etype = typeof e === "string" ? "heuristic" : (e.type || "heuristic");
      addRow("Evidence " + (i + 1) + " Type", etype);
      addRow("Evidence " + (i + 1) + " Text", text);
    });

    var sources = scan.source_breakdown || [];
    sources.forEach(function (s, i) {
      addRow("Source " + (i + 1) + " Type", s.source_type);
      addRow("Source " + (i + 1) + " Engine", s.engine);
      addRow("Source " + (i + 1) + " Verdict", s.verdict);
      addRow("Source " + (i + 1) + " Score", s.score);
      addRow("Source " + (i + 1) + " Note", s.note);

      // ML-specific columns
      if (s.ml_model) {
        addRow("Source " + (i + 1) + " ML Model", s.ml_model);
        addRow("Source " + (i + 1) + " ML Confidence", s.ml_confidence);
        if (s.ml_classes && s.ml_probabilities) {
          s.ml_classes.forEach(function (cls, ci) {
            addRow("Source " + (i + 1) + " Prob " + cls, s.ml_probabilities[ci]);
          });
        }
        if (s.ml_f1_score) {
          addRow("Source " + (i + 1) + " F1 Score", s.ml_f1_score);
        }
        if (s.ml_training_samples) {
          addRow("Source " + (i + 1) + " Training Samples", s.ml_training_samples);
        }
      }
    });

    if (scan.shap_values) {
      scan.shap_values.forEach(function (sv, i) {
        addRow("SHAP Feature " + (i + 1), sv.feature);
        addRow("SHAP Value " + (i + 1), sv.value);
        addRow("SHAP Impact " + (i + 1), sv.impact);
      });
    }

    var csvContent = rows.map(function (row) {
      return row.map(function (cell) {
        return '"' + String(cell).replace(/"/g, '""') + '"';
      }).join(",");
    }).join("\n");

    var blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    var link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = "threatlens_scan_" + (scan.query || "result") + ".csv";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(link.href);
  }

  function renderDetail(detail) {
    var container = document.getElementById("detailPanel");
    if (!container) return;

    var metadata = detail.metadata || {};
    var raw = detail.raw || {};
    var timeline = detail.timeline || {};

    var query = detail.query || detail.source_key || "";
    var srcType = detail.source_type || "";

    var detailQueryEl = document.getElementById("detailQuery");
    if (detailQueryEl) {
      detailQueryEl.textContent = query;
    }

    var metadataHtml = Object.keys(metadata).length
      ? Object.keys(metadata).map(function (k) {
        var v = metadata[k];
        var displayKey = k.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
        return ""
          + '<div class="rounded-xl border border-slate-800 bg-slate-900 p-3">'
          + '<div class="text-xs uppercase tracking-wide text-slate-500">' + escapeHtml(displayKey) + "</div>"
          + '<div class="mt-1 text-sm text-white break-words">' + escapeHtml(Array.isArray(v) ? v.join(", ") : v) + "</div>"
          + "</div>";
      }).join("")
      : '<div class="text-sm text-slate-500">No metadata found.</div>';

    var timelineHtml = Object.keys(timeline).length
      ? Object.keys(timeline).map(function (k) {
        var v = timeline[k];
        var displayKey = k.replace(/_/g, " ").replace(/\b\w/g, function (c) { return c.toUpperCase(); });
        return ""
          + '<div class="flex items-center gap-2 text-xs">'
          + '<span class="text-slate-400 w-28 shrink-0">' + escapeHtml(displayKey) + "</span>"
          + '<span class="text-slate-300">' + escapeHtml(v) + "</span>"
          + "</div>";
      }).join("")
      : '<div class="text-xs text-slate-500">No timeline data available.</div>';

    container.innerHTML = `
        <nav class="mb-4 flex items-center gap-2 text-xs text-slate-500 animate-fadeIn">
            <a href="./index.html" class="hover:text-cyan-400">Home</a>
            <span>/</span>
            ${query ? `<a href="./results.html?q=${encodeURIComponent(query)}" class="hover:text-cyan-400">Results</a><span>/</span>` : ""}
            <span class="text-slate-300">Details</span>
        </nav>

        <div class="rounded-2xl border border-slate-800 bg-slate-900/80 p-6 shadow-2xl shadow-black/20 animate-slideUp max-w-full overflow-hidden">
            <div class="flex flex-wrap items-center gap-2">
                <span class="rounded-full px-3 py-1 text-xs font-semibold ${sourceClass(srcType)}">${escapeHtml(srcType || "UNKNOWN")}</span>
                ${(srcType && (srcType.toUpperCase() === "OTX" || srcType.toUpperCase() === "CVE"))
        ? ""
        : `<span class="rounded-full px-3 py-1 text-xs font-semibold ${verdictPill(detail.verdict)}">${escapeHtml(detail.verdict || "UNKNOWN")}</span>`
      }
                <span class="rounded-full px-3 py-1 text-xs font-semibold ${scorePillClass(detail.score)}">Score ${formatScore(detail.score)}</span>
                <span class="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">${escapeHtml(detail.confidence || "N/A")}</span>
            </div>

            <div class="mt-4 flex flex-col gap-2 md:flex-row md:items-end md:justify-between">
                <div>
                    <h1 class="text-3xl font-bold text-white">${escapeHtml(detail.title || detail.source_key || "Untitled")}</h1>
                    <p class="mt-2 max-w-3xl text-slate-400">${escapeHtml(detail.summary || "No summary available.")}</p>
                </div>
                <div class="font-mono text-sm text-slate-500 select-all break-all">${escapeHtml(detail.source_key || "")}</div>
            </div>

            <div class="mt-6 flex flex-wrap gap-2" id="detailTags"></div>

            <div class="mt-6 rounded-xl border border-slate-800 bg-slate-900/50 p-4">
                <h3 class="text-xs font-semibold uppercase tracking-wide text-slate-400 mb-3">Timeline</h3>
                ${timelineHtml}
            </div>

            <div class="mt-6 grid gap-6" style="grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));">
                <div>
                    <h2 class="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Metadata</h2>
                    <div class="grid gap-3 md:grid-cols-2">${metadataHtml}</div>
                </div>

                <div>
                    <h2 class="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Explainability</h2>
                    <ul id="detailEvidence" class="space-y-3"></ul>
                    <div id="detailShapPanel" class="mt-4"></div>
                </div>

                <div class="md:col-span-full">
                    <div class="flex items-center justify-between mb-3">
                        <h2 class="text-sm font-semibold uppercase tracking-wide text-slate-400">Source breakdown</h2>
                        <span class="text-[10px] text-slate-500">Scroll horizontally if needed →</span>
                    </div>
                    <div id="detailSourceBreakdown" 
                        class="flex gap-4 overflow-x-auto pb-4 scrollbar-thin scrollbar-thumb-slate-700"
                        style="min-height: 200px;">
                        </div>
                </div>

                <div class="md:col-span-full">
                    <div class="mb-3 flex items-center justify-between">
                        <h2 class="text-sm font-semibold uppercase tracking-wide text-slate-400">Raw record</h2>
                        <div class="flex gap-2">
                            <button id="copyRawJson" class="rounded-xl border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700">Copy</button>
                            <button id="toggleRawJson" class="rounded-xl border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-300 hover:bg-slate-700">Toggle</button>
                        </div>
                    </div>
                    <pre id="rawJsonPre" class="overflow-auto rounded-xl border border-slate-800 bg-slate-950 p-4 text-xs text-slate-300 scroll-mt-20">${escapeHtml(JSON.stringify(raw, null, 2))}</pre>
                </div>
            </div>

            <div class="mt-8 flex flex-wrap gap-3">
                <a href="./index.html" class="rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm text-white hover:bg-slate-700">New scan</a>
                <button data-rescan-query="${escapeHtml(query)}" class="rounded-xl bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Re-scan (live API)</button>
            </div>
        </div>
    `;

    renderTags(document.getElementById("detailTags"), detail.tags || []);
    renderEvidence(document.getElementById("detailEvidence"), detail.evidence || []);
    renderSourceBreakdown(document.getElementById("detailSourceBreakdown"), detail.source_breakdown || []);

    var shapContainer = document.getElementById("detailShapPanel");
    if (shapContainer) {
      renderShapPanel(shapContainer, detail.shap_values || []);
    }

    var toggleBtn = document.getElementById("toggleRawJson");
    var rawPre = document.getElementById("rawJsonPre");
    if (toggleBtn && rawPre) {
      var formatted = rawPre.textContent;
      var compact = JSON.stringify(raw);
      var showingFormatted = true;
      toggleBtn.addEventListener("click", function () {
        showingFormatted = !showingFormatted;
        rawPre.textContent = showingFormatted
          ? escapeHtml(JSON.stringify(raw, null, 2))
          : escapeHtml(compact);
        toggleBtn.textContent = showingFormatted ? "Show compact" : "Show formatted";
      });
    }

    var copyBtn = document.getElementById("copyRawJson");
    if (copyBtn && rawPre) {
      copyBtn.addEventListener("click", function () {
        var text = typeof raw === "object" ? JSON.stringify(raw, null, 2) : String(raw);
        navigator.clipboard.writeText(text).then(function () {
          copyBtn.textContent = "Copied!";
          setTimeout(function () { copyBtn.textContent = "Copy"; }, 2000);
        }).catch(function () {
          copyBtn.textContent = "Failed";
        });
      });
    }
  }

  function showInlinePreview(result, query) {
    var previewSection = document.getElementById("scanPreview");
    if (!previewSection) return;

    var scan = result.latest_scan || result;
    var d = scan.detections || {};
    var mal = Number(d.malicious || 0);
    var susp = Number(d.suspicious || 0);
    var clean = Number(d.clean || 0);
    var total = Number(scan.engine_count || mal + susp + clean || 0);
    var evidence = scan.evidence || [];
    var it = (scan.input_type || "").toUpperCase();
    var isOtxCve = it === "OTX" || it === "CVE";

    var calConf = scan.calibrated_confidence;
    var riskBand = scan.risk_band || "";

    previewSection.innerHTML = ""
      + '<div class="rounded-xl border border-slate-800 bg-slate-900/80 p-4 transition-all">'
      + '<div class="flex flex-wrap items-center justify-between gap-3">'
      + '<div class="flex flex-wrap items-center gap-2">'
      + (isOtxCve
        ? '<span class="rounded-full px-2.5 py-0.5 text-xs font-semibold bg-slate-700 text-slate-300">Reference</span>'
        : '<span class="rounded-full px-2.5 py-0.5 text-xs font-semibold ' + verdictPill(scan.verdict) + '">' + escapeHtml(scan.verdict || "UNKNOWN") + "</span>")
      + (riskBand
        ? '<span class="rounded-full px-2.5 py-0.5 text-xs font-semibold ' + riskBandBadgeClass(riskBand) + '">' + escapeHtml(riskBand) + "</span>"
        : "")
      + '<span class="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-300">Score ' + formatScore(scan.score) + "</span>"
      + "</div>"
      + '<span class="text-xs text-slate-500">' + total + " sources</span>"
      + "</div>"
      + (calConf !== null && calConf !== undefined
        ? '<div class="mt-2">'
        + '<div class="flex items-center justify-between text-xs text-slate-400 mb-1">'
        + '<span>Confidence</span>'
        + '<span>' + calConf + '%</span>'
        + "</div>"
        + '<div class="h-1.5 w-full rounded-full bg-slate-700">'
        + '<div class="h-1.5 rounded-full ' + riskBandColor(riskBand) + ' transition-all" style="width: ' + calConf + '%"></div>'
        + "</div>"
        + "</div>"
        : "")
      + (!isOtxCve && total > 0
        ? '<div class="mt-3 grid grid-cols-3 gap-2 text-center text-xs">'
        + '<div class="rounded-lg bg-red-950/40 px-2 py-1.5 text-red-300"><span class="font-semibold">' + mal + '</span> malicious</div>'
        + '<div class="rounded-lg bg-amber-950/40 px-2 py-1.5 text-amber-300"><span class="font-semibold">' + susp + '</span> suspicious</div>'
        + '<div class="rounded-lg bg-emerald-950/40 px-2 py-1.5 text-emerald-300"><span class="font-semibold">' + clean + '</span> clean</div>'
        + "</div>"
        : "")
      + (evidence.length
        ? '<div class="mt-3 text-xs text-slate-400">' + evidence.length + ' explainability note(s) — <a href="results.html?q=' + encodeURIComponent(query) + '" class="text-cyan-400 underline underline-offset-2 hover:text-cyan-300">View full results →</a></div>'
        : '<div class="mt-3 text-xs text-slate-400"><a href="results.html?q=' + encodeURIComponent(query) + '" class="text-cyan-400 underline underline-offset-2 hover:text-cyan-300">View full results →</a></div>')
      + "</div>";

    previewSection.scrollIntoView({ behavior: "smooth", block: "nearest" });
    previewSection.classList.add("scroll-mt-20");

    saveRecentScan({
      query: scan.query || query,
      input_type: scan.input_type || "UNKNOWN",
      verdict: scan.verdict || "UNKNOWN",
      confidence: scan.confidence || "N/A",
      score: scan.score ?? null,
    });

    renderRecentScans();
  }

  async function loadIndexPage() {
    // Guard: only run on index page (has scanForm)
    var scanForm = document.getElementById("scanForm");
    if (!scanForm) return;

    var input = document.getElementById("searchInput");
    var quickHelp = document.getElementById("scanHint");
    var scanButton = document.getElementById("scanButton");

    renderRecentScans();
    renderTipOfTheDay();

    // Load model health bar
    window.ThreatLensAPI.get("/model/status").then(function (resp) {
      renderModelHealthBar(resp.models || resp);
    }).catch(function () { });

    // Define doScan before any usage
    async function doScan(query) {
      if (quickHelp) quickHelp.textContent = "Scanning...";
      if (scanButton) scanButton.disabled = true;
      try {
        var result = await window.ThreatLensAPI.get("/scan?q=" + encodeURIComponent(query));
        showInlinePreview(result, query);
        if (quickHelp) quickHelp.textContent = "Supported: IP, domain, CVE, OTX pulse ID.";
        if (input) input.value = "";
      } catch (error) {
        if (quickHelp) quickHelp.textContent = "Scan failed: " + error.message;
      } finally {
        if (scanButton) scanButton.disabled = false;
      }
    }

    // Character limit counter
    var charCounter = document.getElementById("charCounter");
    if (input && charCounter) {
      input.addEventListener("input", function () {
        var len = input.value.length;
        if (len > 2000) {
          input.value = input.value.substring(0, 2000);
          len = 2000;
        }
        charCounter.textContent = len + " / 2000";
        if (len > 1800) {
          charCounter.className = "text-xs text-red-400";
        } else {
          charCounter.className = "text-xs text-slate-500";
        }
      });
    }

    // Prevent form submission from reloading the page
    scanForm.addEventListener("submit", function (e) {
      e.preventDefault();
    });

    // Enter key triggers scan (Shift+Enter for newline)
    if (input) {
      input.addEventListener("keydown", function (e) {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          var query = input.value.trim();
          if (!query) return;
          doScan(query);
        }
      });
    }

    if (scanButton && input) {
      scanButton.addEventListener("click", function () {
        var query = input.value.trim();
        if (!query) return;
        doScan(query);
      });
    }

    // Set default preview first, so auto-scan can overwrite it
    if (document.getElementById("scanPreview")) {
      document.getElementById("scanPreview").innerHTML = ""
        + '<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center text-sm text-slate-500">'
        + 'Paste an IP, domain, CVE, or OTX pulse ID and press <span class="text-white font-semibold">Scan</span>.'
        + "</div>";
    }

    // Auto-scan if query provided via URL (?q=...)
    var params = new URLSearchParams(window.location.search);
    var urlQuery = params.get("q") || "";
    if (urlQuery) {
      if (input) input.value = urlQuery;
      if (quickHelp) quickHelp.textContent = "Scanning...";
      await doScan(urlQuery);
      var url = new URL(window.location.href);
      url.searchParams.delete("q");
      window.history.replaceState({}, "", url.toString());
    }

    // Bind quick-query buttons to inline preview (dry-run only)
    document.querySelectorAll("[data-quick-query]").forEach(function (btn) {
      btn.addEventListener("click", async function (e) {
        e.preventDefault();
        var query = btn.getAttribute("data-quick-query") || "";
        if (!query) return;
        var dryRun = btn.getAttribute("data-quick-dry-run") === "true";

        if (quickHelp) quickHelp.textContent = "Scanning...";
        try {
          var url = "/scan?q=" + encodeURIComponent(query);
          if (dryRun) url += "&dry_run=true";
          var result = await window.ThreatLensAPI.get(url);
          if (input) input.value = query;
          showInlinePreview(result, query);
          if (quickHelp) quickHelp.textContent = "Supported: IP, domain, CVE, OTX pulse ID.";
        } catch (error) {
          if (quickHelp) quickHelp.textContent = "Demo failed: " + error.message;
        }
      });
    });

    // Listen for SPA scan requests from search.js (e.g. recent scan clicks)
    document.addEventListener("scan-requested", function (e) {
      var query = (e.detail && e.detail.query) || "";
      if (query) {
        if (input) input.value = query;
        doScan(query);
      }
    });

    // Handle back/forward navigation on index page
    window.addEventListener("popstate", function () {
      var params = new URLSearchParams(window.location.search);
      var query = params.get("q") || "";
      if (query) {
        if (input) input.value = query;
        doScan(query);
      }
    });
  }

  async function doScanFromQuery(container, query) {
    var queryLabel = document.getElementById("queryLabel");
    var queryValue = document.getElementById("queryValue");
    if (queryLabel) queryLabel.textContent = query;
    if (queryValue) queryValue.textContent = query;

    var progressId = "scanProgress_" + Date.now();

    container.innerHTML = ""
      + '<div class="transition-opacity" id="' + progressId + '">'
      // Progress indicator
      + '<div class="mb-4 flex items-center gap-2 text-xs text-cyan-400">'
      + '<span class="inline-block h-2 w-2 rounded-full bg-cyan-400 animate-ping"></span>'
      + '<span>Querying APIs... <span class="text-slate-500">(gathering intelligence)</span></span>'
      + "</div>"
      // Verdict skeleton (mirrors the colored band layout)
      + '<div class="animate-pulse rounded-2xl border border-slate-800 bg-slate-900/70 shadow-2xl shadow-black/20 overflow-hidden">'
      + '<div class="bg-slate-800 min-h-32 px-6 py-5">'
      + '<div class="flex items-baseline gap-4">'
      + '<div class="h-10 w-48 rounded bg-slate-700"></div>'
      + '<div class="h-8 w-16 rounded bg-slate-700"></div>'
      + "</div>"
      + '<div class="mt-4">'
      + '<div class="h-3 w-full rounded-full bg-slate-700"></div>'
      + "</div>"
      + "</div>"
      + '<div class="px-6 py-5">'
      + '<div class="h-5 w-64 rounded bg-slate-800"></div>'
      + '<div class="mt-3 h-4 w-full rounded bg-slate-800"></div>'
      + '<div class="mt-5 grid gap-3 grid-cols-3">'
      + '<div class="h-16 rounded-xl bg-slate-800"></div>'
      + '<div class="h-16 rounded-xl bg-slate-800"></div>'
      + '<div class="h-16 rounded-xl bg-slate-800"></div>'
      + "</div>"
      + "</div>"
      + "</div>"
      // Source breakdown skeleton (2-column grid)
      + '<div class="animate-pulse mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">'
      + '<div class="flex items-center justify-between">'
      + '<div class="h-5 w-36 rounded bg-slate-800"></div>'
      + '<div class="h-4 w-24 rounded bg-slate-800"></div>'
      + "</div>"
      + '<div class="mt-4 grid gap-3 grid-cols-2">'
      + '<div class="h-28 rounded-2xl bg-slate-800"></div>'
      + '<div class="h-28 rounded-2xl bg-slate-800"></div>'
      + '<div class="h-28 rounded-2xl bg-slate-800"></div>'
      + '<div class="h-28 rounded-2xl bg-slate-800"></div>'
      + "</div>"
      + "</div>"
      // Evidence skeleton
      + '<div class="animate-pulse mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">'
      + '<div class="flex items-center justify-between">'
      + '<div class="h-5 w-40 rounded bg-slate-800"></div>'
      + '<div class="h-4 w-20 rounded bg-slate-800"></div>'
      + "</div>"
      + '<div class="mt-4 space-y-3">'
      + '<div class="h-12 rounded-xl bg-slate-800"></div>'
      + '<div class="h-12 rounded-xl bg-slate-800"></div>'
      + "</div>"
      + "</div>"
      + "</div>";

    try {
      var result = await window.ThreatLensAPI.get("/scan?q=" + encodeURIComponent(query));

      var scan = result.latest_scan || result;

      // Page transition: fade out progress skeleton, then render with fade-in
      container.classList.add("animate-pageFadeOut");
      await new Promise(function (r) { setTimeout(r, 130); });
      container.classList.remove("animate-pageFadeOut");
      container.classList.add("animate-pageFadeIn");

      // Build full results layout with staggered fade-in
      container.innerHTML = ""
        + '<div id="modelHealthBar" class="mb-4 transition-opacity duration-300"></div>'
        + '<div id="sourcesConsulted" class="mb-4 transition-opacity duration-300"></div>'
        + '<div class="grid gap-6 lg:grid-cols-[1.3fr_0.7fr]">'
        + '<div class="space-y-6">'
        + '<div id="verdictPanel" class="transition-opacity duration-300" style="opacity: 0;"></div>'
        + '<div id="sourceSection" class="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-glow transition-opacity duration-500" style="opacity: 0;">'
        + '<div class="flex items-center justify-between gap-3">'
        + '<h2 class="text-lg font-semibold">Source breakdown</h2>'
        + '<span class="text-xs text-slate-500">Data sources</span>'
        + "</div>"
        + '<div id="sourcePanel" class="mt-4"></div>'
        + "</div>"
        + '<div id="evidenceSection" class="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-glow transition-opacity duration-700" style="opacity: 0;">'
        + '<div class="flex items-center justify-between gap-3">'
        + '<h2 class="text-lg font-semibold">Explainability notes</h2>'
        + '<span class="text-xs text-slate-500">Why this verdict was produced</span>'
        + "</div>"
        + '<ul id="evidenceList" class="mt-4 space-y-3"></ul>'
        + "</div>"
        + "</div>"
        + '<aside class="space-y-6">'
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-glow">'
        + '<h2 class="text-lg font-semibold">Recent scans</h2>'
        + '<div id="recentScans" class="mt-4 space-y-3"></div>'
        + "</div>"
        + '<div class="rounded-2xl border border-slate-800 bg-slate-900/70 p-5 shadow-glow">'
        + '<h2 class="text-lg font-semibold">Scan actions</h2>'
        + '<div class="mt-4 flex flex-col gap-3">'
        + '<button data-rescan-query="' + escapeHtml(query) + '" class="rounded-xl bg-cyan-500 px-5 py-2.5 text-sm font-semibold text-slate-950 hover:bg-cyan-400">Scan again</button>'
        + '<button id="downloadCsvBtn" class="rounded-xl border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm text-slate-200 hover:bg-slate-700">Download CSV</button>'
        + "</div>"
        + "</div>"
        + "</aside>"
        + "</div>";

      renderModelHealthBar(result.model_status);
      renderSourcesConsulted(scan.source_breakdown);

      // Staggered fade-in: verdict → sources → evidence
      var verdictPanel = document.getElementById("verdictPanel");
      var sourceSection = document.getElementById("sourceSection");
      var evidenceSection = document.getElementById("evidenceSection");

      renderVerdictSummary(verdictPanel, scan);
      if (verdictPanel) {
        setTimeout(function () {
          verdictPanel.style.opacity = "1";
          // Animate confidence bar from 0 to final width
          var confBar = verdictPanel.querySelector("[data-conf-width]");
          if (confBar) {
            var targetWidth = confBar.getAttribute("data-conf-width");
            confBar.style.width = targetWidth + "%";
          }
        }, 50);
      }

      renderSourceBreakdown(document.getElementById("sourcePanel"), scan);
      if (sourceSection) setTimeout(function () { sourceSection.style.opacity = "1"; }, 200);

      renderEvidence(document.getElementById("evidenceList"), scan.evidence || []);
      if (evidenceSection) setTimeout(function () { evidenceSection.style.opacity = "1"; }, 400);

      renderRecentScans();

      var csvBtn = document.getElementById("downloadCsvBtn");
      if (csvBtn) {
        csvBtn.addEventListener("click", function () {
          downloadScanCsv(scan);
        });
      }

      saveRecentScan({
        query: scan.query || query,
        input_type: scan.input_type || "UNKNOWN",
        verdict: scan.verdict || "UNKNOWN",
        confidence: scan.confidence || "N/A",
        score: scan.score ?? null,
      });
    } catch (error) {
      container.innerHTML = ""
        + '<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center text-rose-400 animate-shake">'
        + "Scan failed: " + escapeHtml(error.message)
        + "</div>";
    }
  }

  async function loadResultsPage() {
    var container = document.getElementById("resultsShell");
    if (!container) return;

    // Listen for SPA scan requests from search.js
    document.addEventListener("scan-requested", function (e) {
      var query = (e.detail && e.detail.query) || "";
      if (query) {
        doScanFromQuery(container, query);
      }
    });

    // Handle back/forward navigation
    window.addEventListener("popstate", function () {
      var params = new URLSearchParams(window.location.search);
      var query = params.get("q") || "";
      if (query) {
        doScanFromQuery(container, query);
      }
    });

    var params = new URLSearchParams(window.location.search);
    var query = params.get("q") || "";

    if (!query) {
      container.innerHTML = ""
        + '<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center text-sm text-slate-500">'
        + "No query provided."
        + "</div>";
      return;
    }

    await doScanFromQuery(container, query);
  }

  async function loadDetailPage() {
    var container = document.getElementById("detailPanel");
    if (!container) return;

    // Load model health bar
    window.ThreatLensAPI.get("/model/status").then(function (resp) {
      renderModelHealthBar(resp.models || resp);
    }).catch(function () { });

    var params = new URLSearchParams(window.location.search);
    var type = params.get("type");
    var value = params.get("value");

    if (!type || !value) {
      container.innerHTML = ""
        + '<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center text-sm text-slate-500">'
        + "Missing record type or value."
        + "</div>";
      return;
    }

    // Fix header Results link to preserve query
    var resultsLink = document.getElementById("resultsLink");
    if (resultsLink && value) {
      resultsLink.href = "./results.html?q=" + encodeURIComponent(value);
    }

    try {
      var detail = await window.ThreatLensAPI.get("/intel/" + encodeURIComponent(type) + "/" + encodeURIComponent(value));
      renderDetail(detail);
    } catch (error) {
      container.innerHTML = ""
        + '<div class="rounded-xl border border-dashed border-slate-700 bg-slate-900/50 p-8 text-center text-rose-400 animate-shake">'
        + "Unable to load details: " + escapeHtml(error.message)
        + "</div>";
    }
  }

  function init() {
    loadIndexPage();
    loadResultsPage();
    loadDetailPage();
  }

  window.ThreatLensUI = { init: init };
})();
