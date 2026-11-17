/* Показываем только фактическую отправку браузером, проверка выполняется отдельно. */
const form = document.querySelector("[data-core-upload]");
const box = document.querySelector("[data-core-progress]");
const label = box?.querySelector("[data-core-progress-text]");
const bar = box?.querySelector("progress");

if (form && box && label && bar) {
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const button = form.querySelector("button[type=submit]");
    if (button.disabled) return;
    button.disabled = true;
    box.hidden = false;
    label.textContent = "Загрузка пакета…";
    const request = new XMLHttpRequest();
    request.open("POST", form.action);
    request.timeout = 240000;
    request.upload.onprogress = (progress) => {
      if (progress.lengthComputable) {
        bar.value = Math.round(progress.loaded * 100 / progress.total);
        label.textContent = bar.value === 100 ? "Файл загружен, сервер проверяет подпись и состав…" : `Загружено ${bar.value} %`;
      }
    };
    request.onload = () => {
      if (request.status >= 200 && request.status < 400) window.location.assign(form.action.replace(/\/upload$/, ""));
      else {
        label.textContent = "Не удалось загрузить пакет. Проверьте размер и повторите.";
        button.disabled = false;
      }
    };
    request.onerror = request.ontimeout = () => {
      label.textContent = "Связь прервана. Обновите страницу и проверьте состояние пакета.";
      button.disabled = false;
    };
    request.send(new FormData(form));
  });
}

const github = document.querySelector("[data-core-github]");
const githubProgress = document.querySelector("[data-core-github-progress]");
if (github && githubProgress) {
  github.addEventListener("submit", (event) => {
    const button = github.querySelector("button[type=submit]");
    if (button.disabled) {
      event.preventDefault();
      return;
    }
    button.disabled = true;
    githubProgress.hidden = false;
  });
}
