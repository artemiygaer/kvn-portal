(() => {
  "use strict";

  const root = document.documentElement;
  const lang = root.lang === "en" ? "en" : "ru";
  const msg = {
    ru: {
      themeSystem: "системная", themeLight: "светлая", themeDark: "тёмная",
      theme: "Тема", show: "Показать", hide: "Скрыть", showPassword: "Показать пароль", hidePassword: "Скрыть пароль",
      copied: "Содержимое скопировано", copyFailed: "Не удалось скопировать автоматически",
      confirmSuffix: "Это действие может повлиять на доступность.",
      noData: "нет данных", noPeriodData: "За выбранный период данных нет.",
      now: "Сейчас", min: "минимум", max: "максимум", updatingHistory: "Обновляю историю…",
      historyEmpty: "История пока пуста. Первая точка появится в течение минуты.",
      historyLoaded: "Точек", step: "шаг", historyUnavailable: "История временно недоступна. Последние загруженные графики сохранены.",
      refreshPaused: "Обновление приостановлено", nextRefresh: "Следующее обновление через", refreshFailed: "Не удалось обновить. Повтор с задержкой.",
      summaryUpdated: "Сводка обновлена", refreshResumed: "Обновление возобновлено",
      snapshotLoading: "Собираю сводку в фоне…", snapshotStale: "Показаны последние доступные данные.",
      snapshotUpdated: "Состояние актуально.", snapshotUnavailable: "Состояние временно недоступно.",
      logFailed: "Не удалось автоматически обновить логи", logWrap: "Переносить строки", logNoWrap: "Не переносить строки",
      logRefreshing: "Обновляю логи…", logUpdated: "Логи обновлены", logTruncated: "вывод усечён",
      continueLogs: "Продолжить", pause: "Пауза", logsPaused: "Автообновление логов приостановлено", logsResumed: "Автообновление логов возобновлено",
      shownServices: "Показано сервисов",
      shellOffline: "shell отключён", shellConnecting: "подключение…", shellOnline: "root shell активен", shellClosed: "shell закрыт",
      shellReconnecting: "связь с host-agent потеряна, повтор…",
      shellFailed: "Shell недоступен", shellSendFailed: "Не удалось отправить ввод", shellPasswordRequired: "Введите root пароль",
      shellTerminalMissing: "Терминальный эмулятор не загрузился. Обновите страницу и проверьте локальные статические файлы портала.",
      updateUploading: "Загрузка архива", updateVerifying: "Архив передан. Проверяю содержимое…",
      updateReady: "Архив проверен. Показываю команду запуска…", updateFailed: "Не удалось подготовить архив.",
      updateTooLarge: "Шлюз отклонил размер архива. Обновите портал с сервера и повторите.",
      updateGatewayFailed: "Шлюз или портал временно недоступен. Проверьте сервисы на сервере.",
      updateConnectionFailed: "Соединение прервано во время загрузки. Проверьте сеть и повторите.",
      updateAborted: "Загрузка отменена. Можно повторить.", updateStarting: "Передаю команду запуска…",
    },
    en: {
      themeSystem: "system", themeLight: "light", themeDark: "dark",
      theme: "Theme", show: "Show", hide: "Hide", showPassword: "Show password", hidePassword: "Hide password",
      copied: "Copied", copyFailed: "Automatic copy failed",
      confirmSuffix: "This action can affect availability.",
      noData: "no data", noPeriodData: "No data for the selected period.",
      now: "Now", min: "minimum", max: "maximum", updatingHistory: "Updating history…",
      historyEmpty: "History is empty. The first point will appear within a minute.",
      historyLoaded: "Points", step: "step", historyUnavailable: "History is temporarily unavailable. Last loaded charts are kept.",
      refreshPaused: "Refresh paused", nextRefresh: "Next refresh in", refreshFailed: "Refresh failed. Retrying with delay.",
      summaryUpdated: "Dashboard updated", refreshResumed: "Refresh resumed",
      snapshotLoading: "Collecting dashboard in background…", snapshotStale: "Showing last available data.",
      snapshotUpdated: "Status is current.", snapshotUnavailable: "Status is temporarily unavailable.",
      logFailed: "Automatic log refresh failed", logWrap: "Wrap lines", logNoWrap: "Do not wrap lines",
      logRefreshing: "Refreshing logs…", logUpdated: "Logs updated", logTruncated: "output truncated",
      continueLogs: "Continue", pause: "Pause", logsPaused: "Automatic log refresh paused", logsResumed: "Automatic log refresh resumed",
      shownServices: "Visible services",
      shellOffline: "shell offline", shellConnecting: "connecting…", shellOnline: "root shell active", shellClosed: "shell closed",
      shellReconnecting: "host-agent connection lost, retrying…",
      shellFailed: "Shell unavailable", shellSendFailed: "Failed to send input", shellPasswordRequired: "Enter root password",
      shellTerminalMissing: "The terminal emulator did not load. Refresh the page and check the portal static files.",
      updateUploading: "Uploading archive", updateVerifying: "Archive uploaded. Verifying contents…",
      updateReady: "Archive verified. Showing the start command…", updateFailed: "Failed to prepare archive.",
      updateTooLarge: "The gateway rejected the archive size. Update the portal from the server and retry.",
      updateGatewayFailed: "The gateway or portal is temporarily unavailable. Check server services.",
      updateConnectionFailed: "The connection was interrupted during upload. Check the network and retry.",
      updateAborted: "Upload cancelled. You can retry.", updateStarting: "Sending the update command…",
    }
  }[lang];
  const liveRegion = document.querySelector("[data-live-region]");
  const announce = (message) => {
    if (!liveRegion) return;
    liveRegion.textContent = "";
    window.setTimeout(() => { liveRegion.textContent = message; }, 20);
  };

  const savedTheme = localStorage.getItem("kvn-theme");
  if (["light", "dark", "system"].includes(savedTheme)) root.dataset.theme = savedTheme;
  document.querySelector("[data-theme-toggle]")?.addEventListener("click", () => {
    const order = ["system", "light", "dark"];
    const theme = order[(order.indexOf(root.dataset.theme || "system") + 1) % order.length];
    root.dataset.theme = theme;
    localStorage.setItem("kvn-theme", theme);
    announce(`${msg.theme}: ${theme === "system" ? msg.themeSystem : theme === "light" ? msg.themeLight : msg.themeDark}`);
  });

  document.querySelector("[data-password-toggle]")?.addEventListener("click", (event) => {
    const button = event.currentTarget;
    const field = document.getElementById(button.getAttribute("aria-controls"));
    const visible = field.type === "text";
    field.type = visible ? "password" : "text";
    button.textContent = visible ? msg.show : msg.hide;
    button.setAttribute("aria-label", visible ? msg.showPassword : msg.hidePassword);
  });

  const mobileMenu = document.querySelector("[data-mobile-menu]");
  if (mobileMenu) {
    const mobileSummary = mobileMenu.querySelector("summary");
    const closeMobileMenu = (restoreFocus = false) => {
      if (!mobileMenu.open) return;
      mobileMenu.open = false;
      if (restoreFocus) mobileSummary?.focus();
    };
    mobileMenu.addEventListener("keydown", (event) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      closeMobileMenu(true);
    });
    document.addEventListener("pointerdown", (event) => {
      if (event.target instanceof Node && !mobileMenu.contains(event.target)) closeMobileMenu();
    });
    mobileMenu.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => closeMobileMenu()));
  }

  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const source = document.getElementById(button.dataset.copyTarget);
      if (!source) return;
      try {
        await navigator.clipboard.writeText(source.textContent);
        announce(msg.copied);
      } catch (_error) {
        announce(msg.copyFailed);
      }
    });
  });

  const dialog = document.querySelector("[data-confirm-dialog]");
  let pendingForm = null;
  let pendingTrigger = null;
  if (dialog?.showModal) {
    document.querySelectorAll("form[data-confirm]").forEach((form) => {
      form.addEventListener("submit", (event) => {
        if (form.dataset.confirmed === "true") return;
        event.preventDefault();
        pendingForm = form;
        pendingTrigger = event.submitter || document.activeElement;
        const action = form.dataset.confirm || "Выполнить действие";
        const object = form.dataset.object || "объект";
        dialog.querySelector("[data-confirm-text]").textContent = `${action}: ${object}. ${msg.confirmSuffix}`;
        dialog.showModal();
      });
    });
    dialog.addEventListener("close", () => {
      const confirmed = dialog.returnValue === "confirm" && pendingForm;
      if (confirmed) {
        pendingForm.dataset.confirmed = "true";
        pendingForm.requestSubmit();
      } else if (pendingTrigger instanceof HTMLElement) {
        pendingTrigger.focus();
      }
      pendingForm = null;
      pendingTrigger = null;
    });
  }

  document.querySelectorAll("form[data-sensitive-submit]").forEach((form) => {
    const password = form.querySelector("input[type='password']");
    const status = form.querySelector("[data-sensitive-submit-status]");
    const submitButton = form.querySelector("[data-sensitive-submit-button]");
    const clearPassword = () => {
      if (password instanceof HTMLInputElement) password.value = "";
    };
    form.addEventListener("formdata", () => window.setTimeout(clearPassword, 0));
    form.addEventListener("submit", (event) => {
      if (event.defaultPrevented) return;
      form.setAttribute("aria-busy", "true");
      if (status) status.textContent = msg.updateStarting;
      if (submitButton instanceof HTMLButtonElement) submitButton.disabled = true;
    });
  });


  window.KVN = Object.freeze({ msg, announce });

  const commandPalette = document.querySelector("[data-command-palette]");
  const commandSearch = commandPalette?.querySelector("[data-command-search]");
  const commandItems = Array.from(commandPalette?.querySelectorAll("[data-command-item]") || []);
  const commandEmpty = commandPalette?.querySelector("[data-command-empty]");
  const filterCommands = () => {
    const query = (commandSearch?.value || "").trim().toLowerCase();
    let visible = 0;
    commandItems.forEach((item) => {
      const haystack = `${item.textContent} ${item.dataset.keywords || ""}`.toLowerCase();
      const matched = !query || haystack.includes(query);
      item.hidden = !matched;
      if (matched) visible += 1;
    });
    if (commandEmpty) commandEmpty.hidden = visible > 0;
  };
  const openCommandPalette = () => {
    if (!commandPalette?.showModal) return;
    filterCommands();
    commandPalette.showModal();
    window.setTimeout(() => commandSearch?.focus(), 20);
  };
  document.querySelectorAll("[data-command-open]").forEach((button) => button.addEventListener("click", openCommandPalette));
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      openCommandPalette();
    }
  });
  commandSearch?.addEventListener("input", filterCommands);
  commandSearch?.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    const target = commandItems.find((item) => !item.hidden);
    if (target) {
      event.preventDefault();
      target.click();
    }
  });

})();
