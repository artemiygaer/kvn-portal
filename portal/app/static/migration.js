(() => {
  const root = document.querySelector("[data-migration]");
  if (!root) return;
  const csrf = root.dataset.csrf;
  const base = root.dataset.base.replace(/\/$/, "");
  const status = root.querySelector("[data-migration-status]");
  const preview = root.querySelector("[data-migration-preview]");
  const commit = root.querySelector("[data-migration-commit]");
  const apply = root.querySelector("[data-migration-apply]");
  const applyPassword = root.querySelector("[data-migration-root]");
  const cancel = root.querySelector("[data-migration-cancel]");
  const progress = root.querySelector("[data-migration-progress]");
  const stop = root.querySelector("[data-migration-stop]");
  const importForm = root.querySelector("[data-migration-import]");
  const exportForm = root.querySelector("[data-migration-export]");
  const selection = root.querySelector("[data-migration-selection]");
  let pending = null;
  let activeUpload = null;
  let importBusy = false;
  const message = (value) => { status.textContent = value; };
  const request = async (path, body) => {
    const response = await fetch(base + path, {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf}, body: JSON.stringify(body)});
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.ok !== true) throw new Error(result.message || "Операция не выполнена.");
    return result;
  };
  const uploadFile = (file) => new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    activeUpload = xhr;
    xhr.open("POST", base + "/upload");
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-CSRF-Token", csrf);
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) progress.value = Math.round(event.loaded * 100 / event.total);
    };
    xhr.onerror = () => reject(new Error("Не удалось загрузить файл."));
    xhr.onabort = () => reject(new Error("Загрузка отменена."));
    xhr.onload = () => {
      let result;
      try { result = JSON.parse(xhr.responseText); } catch (_) { result = {}; }
      if (xhr.status < 200 || xhr.status >= 300 || result.ok !== true) return reject(new Error(result.message || "Не удалось загрузить файл."));
      resolve(result);
    };
    xhr.send(file);
  });
  exportForm.elements.selection.addEventListener("change", () => { selection.hidden = exportForm.elements.selection.value !== "selected"; });
  exportForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (activeUpload) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const body = {passphrase: fields.get("passphrase"), passphrase_confirmation: fields.get("confirmation"), root_password: fields.get("root_password")};
    if (fields.get("selection") === "selected") body.selected_users = fields.getAll("users");
    message("Шифрование архива…");
    try {
      const result = await request("/export", body);
      window.location.assign(base + "/download/" + encodeURIComponent(result.ticket));
      form.reset();
      selection.hidden = true;
      message("Архив создан. Сохраните его и передайте отдельно от фразы шифрования.");
    } catch (error) { message(error.message); }
  });
  importForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (importBusy) return;
    if (pending) return message("Сначала примените или отмените текущий перенос.");
    pending = null;
    preview.hidden = true;
    apply.hidden = true;
    applyPassword.value = "";
    const fields = new FormData(importForm);
    const file = fields.get("archive");
    if (!file || file.size > 8 * 1024 * 1024 || !file.name.toLowerCase().endsWith(".kvn")) return message("Нужен файл .kvn размером до 8 МиБ.");
    message("Загрузка файла…");
    importBusy = true;
    progress.value = 0;
    progress.hidden = false;
    stop.hidden = false;
    let upload = null;
    try {
      upload = await uploadFile(file);
      activeUpload = null;
      stop.hidden = true;
      message("Проверка архива…");
      const result = await request("/preview", {ticket: upload.ticket, mode: fields.get("mode"),
        passphrase: fields.get("passphrase"), root_password: fields.get("root_password")});
      pending = {ticket: upload.ticket, preview_id: result.preview_id};
      preview.textContent = `Добавить: ${result.add_count}; пропустить: ${result.skip_count}; конфликтов: ${result.conflict_count}. ${result.mode === "restore" ? "VPN-ключи берутся из архива. " : "VPN-ключи сервера сохраняются. "}${result.endpoint_changed ? "Адрес сервера изменится. " : ""}${result.warnings.join(" ")}`;
      preview.hidden = false;
      importForm.querySelector('[name="root_password"]').value = "";
      importForm.querySelector('[name="passphrase"]').value = "";
      apply.hidden = false;
      message("Архив проверен. Применение выполняется отдельной командой.");
    } catch (error) {
      if (upload) await request("/cancel", {ticket: upload.ticket}).catch(() => {});
      importForm.querySelector('[name="root_password"]').value = "";
      importForm.querySelector('[name="passphrase"]').value = "";
      message(error.message);
    } finally { importBusy = false; activeUpload = null; progress.hidden = true; stop.hidden = true; }
  });
  stop.addEventListener("click", () => { if (activeUpload) activeUpload.abort(); });
  cancel.addEventListener("click", async () => {
    if (!pending) return;
    cancel.disabled = true;
    commit.disabled = true;
    try {
      await request("/cancel", pending);
      pending = null;
      apply.hidden = true;
      preview.hidden = true;
      importForm.reset();
      message("Перенос отменён, временные данные удалены.");
    } catch (error) { message(error.message); }
    finally { applyPassword.value = ""; cancel.disabled = false; commit.disabled = false; }
  });
  commit.addEventListener("click", async () => {
    if (!pending) return;
    if (!applyPassword.value) return message("Введите пароль root для применения.");
    commit.disabled = true;
    cancel.disabled = true;
    message("Применение переноса…");
    try {
      await request("/commit", {...pending, root_password: applyPassword.value});
      await request("/cancel", {ticket: pending.ticket}).catch(() => {});
      pending = null;
      importForm.reset();
      preview.hidden = true;
      apply.hidden = true;
      message("Перенос применён. Проверьте подключение пользователей.");
    } catch (error) {
      await request("/cancel", {ticket: pending.ticket}).catch(() => {});
      pending = null;
      apply.hidden = true;
      message(error.message + " Для повторной попытки снова проверьте архив.");
    } finally { applyPassword.value = ""; commit.disabled = false; cancel.disabled = false; }
  });
})();
