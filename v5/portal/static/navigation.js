// Группы навигации доступны и без JavaScript; скрипт добавляет закрытие по Esc и вне меню.
(() => {
    const nav = document.querySelector(".portal-nav");
    if (!nav) return;
    const groups = [...nav.querySelectorAll(".nav-group")];
    document.addEventListener("click", (event) => {
        for (const group of groups) if (group.open && !group.contains(event.target)) group.open = false;
    });
    nav.addEventListener("keydown", (event) => {
        if (event.key !== "Escape") return;
        const group = groups.find((item) => item.open);
        if (!group) return;
        group.open = false;
        group.querySelector("summary").focus();
        event.preventDefault();
    });
})();
