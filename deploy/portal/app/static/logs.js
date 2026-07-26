(() => {
  "use strict";
  const { msg, announce } = window.KVN;

  const logsPanel = document.querySelector("[data-logs-panel]");
  const logView = document.querySelector("[data-log-view]");
  document.querySelector("[data-log-wrap]")?.addEventListener("click", (event) => {
    const wrapped = logView.classList.toggle("wrap");
    event.currentTarget.setAttribute("aria-pressed", String(wrapped));
    event.currentTarget.textContent = wrapped ? msg.logNoWrap : msg.logWrap;
  });
  const logPause = document.querySelector("[data-log-pause]");
  const logStatus = document.querySelector("[data-log-status]");
  const logUpdated = document.querySelector("[data-log-updated]");
  const logCommand = document.querySelector("[data-log-command]");
  const logTruncated = document.querySelector("[data-log-truncated]");
  if (logsPanel && logView && logPause) {
    let logPaused = false;
    let logTimer = null;
    const logsEndpoint = logsPanel.dataset.logsEndpoint;
    const emptyText = logsPanel.dataset.logEmpty || msg.noPeriodData;
    const renderLogTime = (value) => {
      const date = new Date(value);
      return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
    };
    const scheduleLogs = () => {
      window.clearTimeout(logTimer);
      if (!logPaused && !document.hidden) logTimer = window.setTimeout(refreshLogs, 20000);
    };
    const refreshLogs = async () => {
      try {
        if (logStatus) logStatus.textContent = msg.logRefreshing;
        const url = new URL(logsEndpoint, window.location.href);
        url.searchParams.set("_", String(Date.now()));
        const response = await fetch(url.toString(), { headers: { "Accept": "application/json" }, credentials: "same-origin", cache: "no-store" });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        logView.textContent = payload.content || emptyText;
        if (logUpdated) {
          logUpdated.dateTime = payload.generated_at || "";
          logUpdated.textContent = renderLogTime(payload.generated_at || "");
        }
        if (logCommand && payload.command) {
          logCommand.textContent = `${payload.command.source || "logs"} · rc=${payload.command.returncode}`;
          logCommand.className = `status ${payload.command.ok ? "ok" : "down"}`;
        }
        if (logTruncated) logTruncated.hidden = !payload.truncated;
        if (logStatus) logStatus.textContent = payload.truncated ? `${msg.logUpdated}; ${msg.logTruncated}` : msg.logUpdated;
      } catch (_error) {
        if (logStatus) logStatus.textContent = msg.logFailed;
        announce(msg.logFailed);
      } finally {
        scheduleLogs();
      }
    };
    logPause.addEventListener("click", () => {
      logPaused = !logPaused;
      logPause.setAttribute("aria-pressed", String(logPaused));
      logPause.textContent = logPaused ? msg.continueLogs : msg.pause;
      announce(logPaused ? msg.logsPaused : msg.logsResumed);
      scheduleLogs();
    });
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) {
        window.clearTimeout(logTimer);
      } else {
        refreshLogs();
      }
    });
    scheduleLogs();
  }

})();
