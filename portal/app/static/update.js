(() => {
  "use strict";
  const { msg } = window.KVN;

  const updateForm = document.querySelector("form[data-update-prepare]");
  if (updateForm instanceof HTMLFormElement) {
    const fileInput = updateForm.querySelector("input[type='file']");
    const submitButton = updateForm.querySelector("[data-update-submit]");
    const cancelButton = updateForm.querySelector("[data-update-cancel]");
    const retryButton = updateForm.querySelector("[data-update-retry]");
    const progressBox = updateForm.querySelector("[data-update-progress]");
    const progressBar = updateForm.querySelector("[data-update-progress-bar]");
    const status = updateForm.querySelector("[data-update-status]");
    const percent = updateForm.querySelector("[data-update-percent]");
    let updateRequest = null;

    const setUpdateState = (state, value, text) => {
      const normalized = Math.max(0, Math.min(100, Math.round(value || 0)));
      const active = state === "uploading" || state === "verifying";
      updateForm.dataset.updateState = state;
      updateForm.toggleAttribute("aria-busy", active);
      if (progressBox instanceof HTMLElement) {
        progressBox.hidden = state === "idle";
        progressBox.dataset.state = state;
      }
      if (progressBar instanceof HTMLProgressElement) {
        progressBar.value = normalized;
        progressBar.textContent = `${normalized}%`;
        progressBar.setAttribute("aria-valuenow", String(normalized));
      }
      if (percent) percent.textContent = `${normalized}%`;
      if (status) status.textContent = text;
      if (fileInput instanceof HTMLInputElement) fileInput.disabled = active;
      if (submitButton instanceof HTMLButtonElement) submitButton.disabled = active || state === "ready";
      if (cancelButton instanceof HTMLButtonElement) cancelButton.hidden = !active;
      if (retryButton instanceof HTMLButtonElement) retryButton.hidden = state !== "error" && state !== "aborted";
    };

    const failUpdate = (message) => {
      updateRequest = null;
      setUpdateState("error", 0, message || msg.updateFailed);
      window.setTimeout(() => retryButton?.focus(), 0);
    };

    updateForm.addEventListener("submit", (event) => {
      if (event.defaultPrevented || !(fileInput instanceof HTMLInputElement) || !fileInput.files?.length) return;
      event.preventDefault();
      const selectedFile = fileInput.files[0];
      const xhr = new XMLHttpRequest();
      const csrf = updateForm.querySelector("input[name='csrf_token']")?.value || "";
      updateRequest = xhr;
      setUpdateState("uploading", 0, `${msg.updateUploading}: 0%`);
      xhr.open("POST", updateForm.action, true);
      xhr.setRequestHeader("Accept", "application/json");
      xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
      xhr.setRequestHeader("X-CSRF-Token", csrf);
      xhr.setRequestHeader("X-KVN-Archive-Name", selectedFile.name);
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.upload.addEventListener("progress", (progressEvent) => {
        const total = selectedFile.size || progressEvent.total;
        const value = total > 0 ? (progressEvent.loaded / total) * 100 : 0;
        setUpdateState("uploading", value, `${msg.updateUploading}: ${Math.min(100, Math.round(value))}%`);
      });
      xhr.upload.addEventListener("load", () => setUpdateState("verifying", 100, msg.updateVerifying));
      xhr.addEventListener("load", () => {
        let payload = {};
        try {
          payload = JSON.parse(xhr.responseText || "{}");
        } catch (_error) {
          failUpdate(xhr.status === 413 ? msg.updateTooLarge : (xhr.status >= 500 ? msg.updateGatewayFailed : msg.updateFailed));
          return;
        }
        if (xhr.status < 200 || xhr.status >= 300 || payload.ok !== true) {
          failUpdate(typeof payload.error === "string" ? payload.error : msg.updateFailed);
          return;
        }
        updateRequest = null;
        setUpdateState("ready", 100, msg.updateReady);
        window.setTimeout(() => window.location.reload(), 250);
      });
      xhr.addEventListener("error", () => failUpdate(msg.updateConnectionFailed));
      xhr.addEventListener("timeout", () => failUpdate(msg.updateGatewayFailed));
      xhr.addEventListener("abort", () => {
        updateRequest = null;
        setUpdateState("aborted", 0, msg.updateAborted);
        window.setTimeout(() => retryButton?.focus(), 0);
      });
      xhr.send(selectedFile);
    });
    cancelButton?.addEventListener("click", () => updateRequest?.abort());
    retryButton?.addEventListener("click", () => updateForm.requestSubmit());
    fileInput?.addEventListener("change", () => {
      if (!updateRequest) setUpdateState("idle", 0, "");
    });
  }

  const githubRoot = document.querySelector("[data-github-update]");
  if (githubRoot instanceof HTMLElement) {
    const find = (selector) => githubRoot.querySelector(selector);
    const showProgress = (form, state, text) => {
      form.addEventListener("submit", () => {
        const active = state === "checking" || state === "preparing";
        if (!active) return;
        githubRoot.dataset.githubState = state;
        githubRoot.setAttribute("aria-busy", "true");
        find("[data-github-progress]").hidden = false;
        find("[data-github-progress-text]").textContent = text;
        for (const button of githubRoot.querySelectorAll("button")) button.disabled = true;
      });
    };
    const checkForm = find("form[data-github-check]");
    const prepareForm = find("form[data-github-prepare]");
    if (checkForm instanceof HTMLFormElement) {
      showProgress(checkForm, "checking", "Проверка Release…");
    }
    if (prepareForm instanceof HTMLFormElement) {
      showProgress(prepareForm, "preparing", "Скачивание и проверка Release…");
    }
  }

})();
