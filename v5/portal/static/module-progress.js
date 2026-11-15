/* Нативная отправка формы: сервер определяет итог; проценты не выдумываем. */
const progress = document.querySelector("[data-operation-progress]");
const message = progress?.querySelector("[data-operation-text]");

if (progress && message) {
  let pending = false;
  document.querySelector("main").addEventListener("submit", (event) => {
    if (event.defaultPrevented || !(event.target instanceof HTMLFormElement)) return;
    if (pending) {
      event.preventDefault();
      return;
    }
    pending = true;
    const action = event.submitter?.textContent.trim() || "Операция модуля";
    message.textContent = `${action}: запрос выполняется. Дождитесь результата.`;
    event.target.before(progress);
    progress.hidden = false;
  });
  window.addEventListener("pageshow", () => {
    pending = false;
    progress.hidden = true;
    message.textContent = "";
  });
}
