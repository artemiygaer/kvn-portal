(() => {
  "use strict";

  const userActivity = document.querySelector("[data-user-activity]");
  const userEvents = document.querySelector("[data-user-events]");
  if (!userActivity || !userEvents) return;

  const lang = document.documentElement.lang === "en" ? "en" : "ru";
  const msg = {
    ru: {
      loading: "Получаю безопасную runtime-сводку…", updated: "Активность обновлена",
      failed: "Активность временно недоступна", empty: "Для пользователя нет назначенных протоколов.",
      eventsEmpty: "Действий пользователя пока нет."
    },
    en: {
      loading: "Loading privacy-safe runtime summary…", updated: "Activity updated",
      failed: "Activity is temporarily unavailable", empty: "No protocols are assigned to this user.",
      eventsEmpty: "No user management events yet."
    }
  }[lang];
  const activityRows = userActivity.querySelector("[data-user-activity-rows]");
  const eventRows = userEvents.querySelector("[data-user-event-rows]");
  const activityStatus = userActivity.querySelector("[data-user-activity-status]");
  const refreshButtons = document.querySelectorAll("[data-user-activity-refresh]");
  let loading = false;

  const createText = (tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value;
    return node;
  };
  const formatBytes = (value) => {
    if (!Number.isSafeInteger(value) || value < 0) return "—";
    const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
    let current = value;
    let unit = 0;
    while (current >= 1024 && unit < units.length - 1) { current /= 1024; unit += 1; }
    return `${unit ? current.toFixed(current >= 10 ? 1 : 2) : current} ${units[unit]}`;
  };
  const statusLabels = {
    active: "активен", observed: "есть трафик", idle: "нет активности", stale: "давно не активен",
    disabled: "отключён", unsupported: "нет персональной статистики", unavailable: "источник недоступен"
  };
  const statusClasses = {
    active: "on", observed: "ok", idle: "stale", stale: "stale",
    disabled: "off", unsupported: "stale", unavailable: "down"
  };
  const reasonLabels = {
    shared_secret_has_no_attribution: "Общий secret не позволяет различать пользователей.",
    per_user_metrics_not_exposed: "Текущая версия не отдаёт персональные метрики.",
    per_user_fields_not_exposed: "Персональные поля трафика не поддерживаются.",
    user_or_service_disabled: "Пользователь или сервис отключён.",
    peer_not_applied: "Peer пока не применён в runtime.", public_key_missing: "Public key ещё не подготовлен.",
    interface_unavailable: "Интерфейс недоступен.", api_unavailable: "Локальный API недоступен.",
    not_configured: "Источник не настроен.", invalid_response: "Источник вернул некорректный ответ.",
    total_timeout: "Превышен общий лимит ожидания.", command_timeout: "Превышен лимит ожидания команды.",
    adapter_failed: "Адаптер завершился с ошибкой."
  };
  const actionLabels = {
    "user.create": "Пользователь создан", "user.update": "Профиль изменён",
    "user.set-enabled": "Статус изменён", "user.delete": "Пользователь удалён",
    "user.rotate": "Ключи обновлены", "user.rotate-subscription": "Токен подписки обновлён",
    "user.reset-ocserv": "Пароль OpenConnect обновлён", "user.link.download": "Файл скачан",
    "user.link.preview": "Файл открыт"
  };
  const resultLabels = { success: "успешно", failed: "ошибка", unchanged: "без изменений" };

  const renderActivity = (items) => {
    activityRows.replaceChildren();
    if (!Array.isArray(items) || !items.length) {
      activityRows.append(createText("p", "empty-state", msg.empty));
      return;
    }
    items.forEach((item) => {
      const card = document.createElement("article");
      card.className = "activity-card";
      card.append(createText("h3", "", item.label || item.system || "—"));
      card.append(createText("span", `status ${statusClasses[item.status] || "stale"}`, statusLabels[item.status] || item.status || "—"));
      const metrics = document.createElement("dl");
      metrics.className = "activity-metrics";
      const pairs = [];
      if (Number.isSafeInteger(item.uplink_bytes)) pairs.push(["Отправлено", formatBytes(item.uplink_bytes)]);
      if (Number.isSafeInteger(item.downlink_bytes)) pairs.push(["Получено", formatBytes(item.downlink_bytes)]);
      if (Number.isSafeInteger(item.rx_bytes)) pairs.push(["RX", formatBytes(item.rx_bytes)]);
      if (Number.isSafeInteger(item.tx_bytes)) pairs.push(["TX", formatBytes(item.tx_bytes)]);
      if (Number.isSafeInteger(item.connections)) pairs.push(["Подключения", String(item.connections)]);
      if (Number.isSafeInteger(item.last_activity) && item.last_activity > 0) pairs.push(["Последняя активность", new Date(item.last_activity * 1000).toLocaleString()]);
      pairs.forEach(([label, value]) => {
        const cell = document.createElement("div");
        cell.append(createText("dt", "", label), createText("dd", "", value));
        metrics.append(cell);
      });
      if (pairs.length) card.append(metrics);
      if (item.reason) card.append(createText("p", "muted", reasonLabels[item.reason] || "Источник не предоставил данные."));
      activityRows.append(card);
    });
  };
  const renderEvents = (items) => {
    eventRows.replaceChildren();
    if (!Array.isArray(items) || !items.length) {
      eventRows.append(createText("p", "empty-state", msg.eventsEmpty));
      return;
    }
    items.forEach((item) => {
      const row = document.createElement("article");
      const eventTime = document.createElement("time");
      const date = new Date(Number(item.created_at) * 1000);
      row.className = "event-row";
      eventTime.dateTime = Number.isNaN(date.getTime()) ? "" : date.toISOString();
      eventTime.textContent = Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
      row.append(eventTime, createText("strong", "", actionLabels[item.action] || item.action || "—"));
      row.append(createText("span", `status ${item.result === "success" ? "ok" : item.result === "failed" ? "down" : "stale"}`, resultLabels[item.result] || item.result || "—"));
      eventRows.append(row);
    });
  };
  const refreshActivity = async () => {
    if (loading) return;
    loading = true;
    refreshButtons.forEach((button) => { button.disabled = true; });
    if (activityStatus) activityStatus.textContent = msg.loading;
    try {
      const response = await fetch(userActivity.dataset.endpoint, {
        headers: { "Accept": "application/json" }, credentials: "same-origin", cache: "no-store"
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      if (payload.ok !== true) throw new Error("invalid payload");
      renderActivity(payload.activity?.systems);
      renderEvents(payload.events);
      const updatedAt = Number(payload.activity?.generated_at) * 1000;
      const suffix = updatedAt > 0 ? ` · ${new Date(updatedAt).toLocaleTimeString()}` : "";
      if (activityStatus) activityStatus.textContent = `${msg.updated}${suffix}`;
    } catch (_error) {
      if (activityStatus) activityStatus.textContent = msg.failed;
      const liveRegion = document.querySelector("[data-live-region]");
      if (liveRegion) liveRegion.textContent = msg.failed;
    } finally {
      loading = false;
      refreshButtons.forEach((button) => { button.disabled = false; });
    }
  };
  refreshButtons.forEach((button) => button.addEventListener("click", refreshActivity));
  if (userActivity.dataset.backgroundRefresh !== "false") {
    refreshActivity();
    window.setInterval(() => { if (!document.hidden) refreshActivity(); }, 60000);
  }
})();
