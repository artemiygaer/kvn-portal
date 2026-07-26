(() => {
  "use strict";
  const { msg, announce } = window.KVN;

  const dashboard = document.querySelector("[data-dashboard]");
  if (dashboard) {
    const monitoringEnabled = dashboard.dataset.monitoringEnabled !== "false";
    const backgroundRefresh = dashboard.dataset.backgroundRefresh !== "false";
    const pollStatus = dashboard.querySelector("[data-poll-status]");
    const refreshButton = dashboard.querySelector("[data-dashboard-refresh]");
    const history = document.querySelector("[data-history]");
    const historyStatus = history?.querySelector("[data-history-status]");
    const rangeControl = history?.querySelector("[data-history-range]");
    const stepControl = history?.querySelector("[data-history-step]");
    let timer = null;
    let failures = 0;
    let polling = false;
    let stateHint = "";
    let lastHistoryAt = 0;
    const formatNumber = (value, unit) => {
      if (!Number.isFinite(value)) return msg.noData;
      if (unit === "%") return `${value.toFixed(1)}%`;
      if (unit === "Б/с") {
        const units = ["Б/с", "КиБ/с", "МиБ/с", "ГиБ/с"];
        let number = value;
        let index = 0;
        while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
        return `${number.toFixed(index ? 1 : 0)} ${units[index]}`;
      }
      if (unit === "Б") {
        const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
        let number = value;
        let index = 0;
        while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
        return `${number.toFixed(index ? 1 : 0)} ${units[index]}`;
      }
      return value.toFixed(unit ? 1 : 2);
    };
    const renderChart = (card, points) => {
      const key = card.dataset.metric;
      const unit = card.dataset.unit;
      const values = points.map((point) => Number(point[key])).filter(Number.isFinite);
      const line = card.querySelector("[data-chart-line]");
      const area = card.querySelector("[data-chart-area]");
      const summary = card.querySelector("[data-chart-summary]");
      const description = card.querySelector("desc");
      const nowNode = card.querySelector("[data-chart-now]");
      const minNode = card.querySelector("[data-chart-min]");
      const maxNode = card.querySelector("[data-chart-max]");
      if (!values.length) {
        line.setAttribute("d", "");
        area.setAttribute("d", "");
        summary.textContent = msg.noPeriodData;
        description.textContent = summary.textContent;
        [nowNode, minNode, maxNode].forEach((node) => { if (node) node.textContent = "—"; });
        return;
      }
      const width = 600;
      const height = 180;
      const padding = 14;
      const fixedMax = Number(card.dataset.max);
      const maximum = fixedMax > 0 ? fixedMax : Math.max(...values, 1);
      const coordinates = points.map((point, index) => {
        const value = Number(point[key]);
        if (!Number.isFinite(value)) return null;
        const x = padding + index * (width - padding * 2) / Math.max(points.length - 1, 1);
        const y = height - padding - Math.max(0, Math.min(maximum, value)) * (height - padding * 2) / maximum;
        return [x, y, value];
      }).filter(Boolean);
      const path = coordinates.map((item, index) => `${index ? "L" : "M"}${item[0].toFixed(1)},${item[1].toFixed(1)}`).join(" ");
      line.setAttribute("d", path);
      area.setAttribute("d", `${path} L${coordinates.at(-1)[0].toFixed(1)},${height - padding} L${coordinates[0][0].toFixed(1)},${height - padding} Z`);
      const numeric = coordinates.map((item) => item[2]);
      const current = numeric.at(-1);
      const minimum = Math.min(...numeric);
      const max = Math.max(...numeric);
      const latestPoint = points.at(-1) || {};
      const extraCurrentKey = card.dataset.extraCurrent;
      const extraTotalKey = card.dataset.extraTotal;
      const extraUnit = card.dataset.extraUnit || "";
      const extraLabel = card.dataset.extraLabel || "";
      const extraCurrent = Number(latestPoint[extraCurrentKey]);
      const extraTotal = Number(latestPoint[extraTotalKey]);
      let extraText = "";
      if (extraCurrentKey && Number.isFinite(extraCurrent) && Number.isFinite(extraTotal) && extraTotal > 0) {
        extraText = ` · ${extraLabel} ${formatNumber(extraCurrent, extraUnit)} / ${formatNumber(extraTotal, extraUnit)}`;
      } else if (extraCurrentKey && Number.isFinite(extraCurrent)) {
        extraText = ` · ${extraLabel} ${formatNumber(extraCurrent, extraUnit)}`;
      }
      if (nowNode) nowNode.textContent = `${formatNumber(current, unit)}${extraText}`;
      if (minNode) minNode.textContent = formatNumber(minimum, unit);
      if (maxNode) maxNode.textContent = formatNumber(max, unit);
      summary.textContent = `${msg.now} ${formatNumber(current, unit)}${extraText} · ${msg.min} ${formatNumber(minimum, unit)} · ${msg.max} ${formatNumber(max, unit)}`;
      description.textContent = summary.textContent;
    };
    const normalizeHistoryControls = () => {
      if (!rangeControl || !stepControl) return;
      if (rangeControl.value === "72" && stepControl.value === "1") stepControl.value = "5";
      localStorage.setItem("kvn-history-range", rangeControl.value);
      localStorage.setItem("kvn-history-step", stepControl.value);
    };
    const loadHistory = async () => {
      if (!history) return;
      normalizeHistoryControls();
      history.setAttribute("aria-busy", "true");
      historyStatus.textContent = msg.updatingHistory;
      const query = new URLSearchParams({ range_hours: rangeControl.value, step: stepControl.value });
      try {
        const response = await fetch(`${dashboard.dataset.historyEndpoint}?${query}`, { headers: { "Accept": "application/json" }, credentials: "same-origin" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        history.querySelectorAll("[data-chart]").forEach((card) => renderChart(card, payload.points || []));
        historyStatus.textContent = payload.points?.length ? `${msg.historyLoaded}: ${payload.points.length}, ${msg.step}: ${payload.step_minutes} min.` : msg.historyEmpty;
        lastHistoryAt = Date.now();
      } catch (_error) {
        historyStatus.textContent = msg.historyUnavailable;
      } finally {
        history.setAttribute("aria-busy", "false");
      }
    };
    const savedRange = localStorage.getItem("kvn-history-range");
    const savedStep = localStorage.getItem("kvn-history-step");
    if (rangeControl && ["1", "6", "24", "72"].includes(savedRange)) rangeControl.value = savedRange;
    if (stepControl && ["auto", "1", "5", "15", "60"].includes(savedStep)) stepControl.value = savedStep;
    rangeControl?.addEventListener("change", loadHistory);
    stepControl?.addEventListener("change", loadHistory);
    const schedule = () => {
      if (!backgroundRefresh) {
        window.clearTimeout(timer);
        pollStatus.textContent = "Только ручное обновление";
        return;
      }
      const delay = Math.min(240000, 60000 * (2 ** failures));
      window.clearTimeout(timer);
      if (!document.hidden) timer = window.setTimeout(poll, delay);
      pollStatus.textContent = document.hidden ? msg.refreshPaused : (stateHint || `${msg.nextRefresh} ${delay / 1000} s`);
    };
    const poll = async () => {
      if (document.hidden) return schedule();
      if (polling) return;
      polling = true;
      dashboard.setAttribute("aria-busy", "true");
      try {
        const response = await fetch(dashboard.dataset.endpoint, { headers: { "Accept": "application/json" }, credentials: "same-origin" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        (payload.cards || []).forEach((item) => {
          const card = dashboard.querySelector(`[data-card="${CSS.escape(item.id)}"]`);
          if (!card) return;
          const status = card.querySelector("[data-card-status]");
          status.className = `status ${item.status}`;
          status.textContent = item.status_label;
          card.querySelector("[data-card-value]").textContent = item.value;
          card.querySelector("[data-card-detail]").textContent = item.detail;
        });
        failures = 0;
        stateHint = payload.status === "loading" ? msg.snapshotLoading : payload.stale ? msg.snapshotStale : "";
        if (monitoringEnabled && Date.now() - lastHistoryAt >= 180000) loadHistory();
        announce(msg.summaryUpdated);
      } catch (_error) {
        failures = Math.min(failures + 1, 2);
        stateHint = msg.refreshFailed;
      } finally {
        polling = false;
        dashboard.setAttribute("aria-busy", "false");
        if (backgroundRefresh) schedule();
      }
    };
    refreshButton?.addEventListener("click", poll);
    if (backgroundRefresh) {
      document.addEventListener("visibilitychange", () => {
        if (document.hidden) window.clearTimeout(timer); else schedule();
        pollStatus.textContent = document.hidden ? msg.refreshPaused : msg.refreshResumed;
      });
      if (monitoringEnabled) loadHistory();
      poll();
    }
  }

})();
