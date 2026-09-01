(function () {
  "use strict";

  document.querySelectorAll("[data-ticket-tabs]").forEach(function (tabs) {
    var tabList = tabs.querySelector("[role='tablist']");
    var tabButtons = Array.from(tabs.querySelectorAll("[role='tab']"));
    var panels = Array.from(tabs.querySelectorAll("[role='tabpanel']"));

    function activateTab(selectedTab, moveFocus) {
      tabButtons.forEach(function (tab) {
        var isSelected = tab === selectedTab;
        tab.setAttribute("aria-selected", String(isSelected));
        tab.tabIndex = isSelected ? 0 : -1;
      });

      panels.forEach(function (panel) {
        panel.hidden = panel.id !== selectedTab.getAttribute("aria-controls");
      });

      if (moveFocus) {
        selectedTab.focus();
      }
    }

    tabButtons.forEach(function (tab) {
      tab.addEventListener("click", function () {
        activateTab(tab, false);
      });
    });

    tabList.addEventListener("keydown", function (event) {
      var currentIndex = tabButtons.indexOf(document.activeElement);
      if (currentIndex < 0) return;

      var nextIndex = null;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") {
        nextIndex = (currentIndex + 1) % tabButtons.length;
      } else if (event.key === "ArrowLeft" || event.key === "ArrowUp") {
        nextIndex = (currentIndex - 1 + tabButtons.length) % tabButtons.length;
      } else if (event.key === "Home") {
        nextIndex = 0;
      } else if (event.key === "End") {
        nextIndex = tabButtons.length - 1;
      }

      if (nextIndex !== null) {
        event.preventDefault();
        activateTab(tabButtons[nextIndex], true);
      }
    });
  });
})();
