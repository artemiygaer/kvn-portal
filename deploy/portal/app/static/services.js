(() => {
  "use strict";
  const { msg, announce } = window.KVN;

  const serviceCards = Array.from(document.querySelectorAll("[data-service-card]"));
  const serviceFilter = document.querySelector("[data-service-filter]");
  const serviceStatus = document.querySelector("[data-service-status]");
  const serviceKind = document.querySelector("[data-service-kind]");
  const serviceEmpty = document.querySelector("[data-service-empty]");
  const serviceCount = document.querySelector("[data-service-count]");
  const filterServices = () => {
    const query = (serviceFilter?.value || "").trim().toLowerCase();
    const status = serviceStatus?.value || "all";
    const kind = serviceKind?.value || "all";
    let visible = 0;
    serviceCards.forEach((card) => {
      const matchesQuery = !query || (card.dataset.serviceName || "").includes(query);
      const matchesStatus = status === "all" || card.dataset.serviceActive === status;
      const matchesKind = kind === "all" || card.dataset.serviceKind === kind;
      const matched = matchesQuery && matchesStatus && matchesKind;
      card.hidden = !matched;
      if (matched) visible += 1;
    });
    if (serviceEmpty) serviceEmpty.hidden = visible > 0;
    if (serviceCount) serviceCount.textContent = serviceCards.length ? `${msg.shownServices}: ${visible}/${serviceCards.length}` : "";
  };
  [serviceFilter, serviceStatus, serviceKind].forEach((control) => control?.addEventListener("input", filterServices));
  filterServices();

})();
