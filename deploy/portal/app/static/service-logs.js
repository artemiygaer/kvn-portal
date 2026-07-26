(() => {
  "use strict";

  const panels = document.querySelectorAll("[data-inline-log-panel]");
  panels.forEach((panel) => {
    const toggle = document.querySelector(`[aria-controls="${panel.id}"]`);
    const refresh = panel.querySelector("[data-inline-log-refresh]");
    const status = panel.querySelector("[data-inline-log-status]");
    const view = panel.querySelector("[data-inline-log-view]");
    let loaded = false;
    let loading = false;

    const setLoading = (value) => {
      loading = value;
      if (toggle) toggle.disabled = value;
      if (refresh) refresh.disabled = value;
    };
    const loadLogs = async () => {
      if (loading) return;
      setLoading(true);
      status.textContent = "Получаю ограниченную выборку…";
      try {
        const response = await fetch(panel.dataset.inlineLogEndpoint, {
          headers: { "Accept": "application/json" },
          credentials: "same-origin",
          cache: "no-store"
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        if (!payload || typeof payload.content !== "string") throw new Error("invalid payload");
        view.textContent = payload.content || "За выбранный период записей нет.";
        const failed = payload.command && payload.command.ok === false;
        status.textContent = failed
          ? "Сервис остановлен или источник журнала временно недоступен."
          : payload.truncated ? "Журнал обновлён; вывод усечён." : "Журнал обновлён.";
        loaded = true;
      } catch (_error) {
        view.textContent = "Не удалось получить журнал. Откройте полный журнал для диагностики.";
        status.textContent = "Журнал временно недоступен.";
      } finally {
        setLoading(false);
      }
    };

    toggle?.addEventListener("click", () => {
      const expanded = toggle.getAttribute("aria-expanded") !== "true";
      toggle.setAttribute("aria-expanded", String(expanded));
      panel.hidden = !expanded;
      if (expanded && !loaded) loadLogs();
    });
    refresh?.addEventListener("click", loadLogs);
  });
})();
