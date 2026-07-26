(() => {
  "use strict";
  const { msg, announce } = window.KVN;

  const userFilter = document.querySelector("[data-user-live-filter]");
  const userItems = Array.from(document.querySelectorAll("[data-user-item]"));
  const userNoMatch = document.querySelector("[data-users-client-no-match]");
  if (userFilter && userItems.length) {
    const filterUsers = () => {
      const query = userFilter.value.trim().toLowerCase();
      let visible = 0;
      userItems.forEach((item) => {
        const matches = !query || (item.dataset.search || "").toLowerCase().includes(query);
        item.hidden = !matches;
        if (matches) visible += 1;
      });
      if (userNoMatch) userNoMatch.hidden = visible !== 0;
    };
    userFilter.addEventListener("input", filterUsers);
  }

})();
