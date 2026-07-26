(() => {
  "use strict";
  const { msg, announce } = window.KVN;

  const networkPanel = document.querySelector("[data-network]");
  if (networkPanel) {
    const filter = networkPanel.querySelector("[data-network-filter]");
    const empty = networkPanel.querySelector("[data-network-empty]");
    const status = networkPanel.querySelector("[data-network-status]");
    const cards = Array.from(networkPanel.querySelectorAll("[data-protocol-card]"));
    const applyFilter = () => {
      const query = (filter?.value || "").trim().toLowerCase();
      let visible = 0;
      cards.forEach((card) => {
        const matches = !query || (card.dataset.search || "").toLowerCase().includes(query);
        card.hidden = !matches;
        if (matches) visible += 1;
      });
      if (empty) empty.hidden = visible !== 0;
    };
    const refreshNetwork = async () => {
      try {
        networkPanel.setAttribute("aria-busy", "true");
        const response = await fetch(networkPanel.dataset.endpoint, {
          headers: { "Accept": "application/json" }, credentials: "same-origin", cache: "no-store"
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        const bySystem = new Map((payload.protocols || []).map((item) => [item.system, item]));
        cards.forEach((card) => {
          const runtime = bySystem.get(card.dataset.protocol)?.runtime;
          const badge = card.querySelector("[data-runtime-status]");
          if (badge && runtime) {
            badge.textContent = runtime.label || "—";
            badge.className = `status ${runtime.status || "stale"}`;
          }
        });
        if (status) {
          status.textContent = payload.error || (payload.stale ? msg.snapshotStale : msg.snapshotUpdated);
          status.className = `status ${payload.error ? "down" : (payload.stale ? "stale" : "ok")}`;
        }
      } catch (_error) {
        if (status) {
          status.textContent = msg.snapshotUnavailable;
          status.className = "status down";
        }
      } finally {
        networkPanel.setAttribute("aria-busy", "false");
      }
    };
    filter?.addEventListener("input", applyFilter);
    document.querySelector("[data-network-refresh]")?.addEventListener("click", refreshNetwork);
    if (networkPanel.dataset.backgroundRefresh !== "false") {
      window.setInterval(() => { if (!document.hidden) refreshNetwork(); }, 30000);
    }
  }
})();
