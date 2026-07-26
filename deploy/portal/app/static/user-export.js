(() => {
  "use strict";

  const dialog = document.querySelector("[data-user-export-dialog]");
  const triggers = document.querySelectorAll("[data-user-export-trigger]");
  let activeTrigger = null;

  const modeUrl = (base, mode) => {
    const url = new URL(base, window.location.href);
    url.searchParams.set("address_mode", mode);
    return `${url.pathname}${url.search}`;
  };

  if (dialog?.showModal && triggers.length) {
    const userLabel = dialog.querySelector("[data-export-user]");
    const status = dialog.querySelector("[data-export-status]");
    const zipLink = dialog.querySelector("[data-export-zip]");
    const textLink = dialog.querySelector("[data-export-text-download]");
    const alternateLink = dialog.querySelector("[data-export-alternate]");
    const copyButton = dialog.querySelector("[data-export-copy]");
    const radios = Array.from(dialog.querySelectorAll("[data-export-mode]"));
    let zipBase = "";
    let textBase = "";

    const selectedMode = () => radios.find((radio) => radio.checked)?.value || "server";
    const updateActions = () => {
      const mode = selectedMode();
      const label = mode === "public-ip" ? "публичный IP" : "домен";
      zipLink.href = modeUrl(zipBase, mode);
      textLink.href = modeUrl(textBase, mode);
      status.textContent = `Выбран адрес: ${label}. Настройки сервера не изменятся.`;
      if (
        dialog.dataset.includeAlternate === "true"
        && !radios.find((radio) => radio.value === "public-ip")?.disabled
      ) {
        const alternate = mode === "public-ip" ? "server" : "public-ip";
        alternateLink.href = modeUrl(zipBase, alternate);
        alternateLink.textContent = `Скачать резервный ZIP (${alternate === "public-ip" ? "IP" : "домен"})`;
        alternateLink.hidden = false;
      } else {
        alternateLink.hidden = true;
      }
    };

    triggers.forEach((trigger) => {
      trigger.addEventListener("click", (event) => {
        event.preventDefault();
        activeTrigger = trigger;
        zipBase = trigger.dataset.exportZipUrl;
        textBase = trigger.dataset.exportTextUrl;
        userLabel.textContent = trigger.dataset.userName;
        const defaultMode = dialog.dataset.defaultMode || "server";
        const requested = radios.find((radio) => radio.value === defaultMode && !radio.disabled);
        (requested || radios.find((radio) => !radio.disabled)).checked = true;
        updateActions();
        dialog.showModal();
        window.setTimeout(() => {
          radios.find((radio) => radio.checked)?.focus();
        }, 20);
      });
    });
    radios.forEach((radio) => radio.addEventListener("change", updateActions));
    [zipLink, textLink, alternateLink].forEach((link) => {
      link.addEventListener("click", () => {
        status.textContent = "Скачивание началось. Файл не сохраняется на портале.";
      });
    });
    copyButton.addEventListener("click", async () => {
      copyButton.disabled = true;
      status.textContent = "Получаю текст по защищённому no-store запросу…";
      try {
        const response = await fetch(modeUrl(textBase, selectedMode()), {
          credentials: "same-origin",
          cache: "no-store",
          headers: { Accept: "text/plain" },
        });
        if (!response.ok || !response.headers.get("content-type")?.startsWith("text/plain")) {
          throw new Error("export unavailable");
        }
        const payload = await response.text();
        if (!payload || payload.length > 65_536 || !navigator.clipboard?.writeText) {
          throw new Error("clipboard unavailable");
        }
        await navigator.clipboard.writeText(payload);
        status.textContent = `Текст скопирован (${selectedMode() === "public-ip" ? "IP" : "домен"}).`;
        window.KVN?.announce("Текст конфигурации скопирован");
      } catch (_error) {
        status.textContent = "Не удалось скопировать. Скачайте send.txt или повторите позже.";
        window.KVN?.announce("Экспорт временно недоступен");
      } finally {
        copyButton.disabled = false;
      }
    });
    dialog.addEventListener("close", () => {
      if (activeTrigger instanceof HTMLElement) activeTrigger.focus();
      activeTrigger = null;
    });
  }

  const settingsForm = document.querySelector("[data-client-export-form]");
  if (!settingsForm) return;
  const ipField = settingsForm.querySelector("[name='public_ip']");
  const alternate = settingsForm.querySelector("[name='include_alternate']");
  const preview = settingsForm.querySelector("[data-client-export-preview]");
  const error = settingsForm.querySelector("[data-client-export-error]");
  const modes = Array.from(settingsForm.querySelectorAll("[name='address_mode']"));

  const isPublicIpv4 = (value) => {
    const parts = value.split(".");
    if (parts.length !== 4 || parts.some((part) => !/^(0|[1-9]\d{0,2})$/.test(part))) return false;
    const octets = parts.map(Number);
    if (octets.some((part) => part > 255)) return false;
    const [a, b, c] = octets;
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0 && [0, 2].includes(c))
      || (a === 198 && [18, 19].includes(b))
      || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113)
    );
  };

  const validate = () => {
    const mode = modes.find((item) => item.checked)?.value || "";
    const ip = ipField.value.trim();
    const required = mode === "public-ip" || alternate.checked;
    let message = "";
    if (!mode) message = "Выберите основной адрес.";
    else if (required && !ip) message = "Укажите публичный IPv4.";
    else if (ip && !isPublicIpv4(ip)) message = "Нужен публичный глобальный IPv4.";
    ipField.setCustomValidity(message);
    error.textContent = message;
    preview.textContent = message
      ? "Предпросмотр недоступен: исправьте IPv4."
      : `Основной endpoint: ${mode === "public-ip" ? ip : "домен сервера"}.`;
    return !message;
  };
  modes.forEach((item) => item.addEventListener("change", validate));
  ipField.addEventListener("input", validate);
  alternate.addEventListener("change", validate);
  settingsForm.addEventListener("submit", (event) => {
    if (validate()) return;
    event.preventDefault();
    ipField.reportValidity();
  });
  validate();
})();
