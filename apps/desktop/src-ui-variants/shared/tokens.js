// 公共小件：品牌图标（F + 右下角圆点，和 exe 图标同一套几何）。
"use strict";

(function () {
  const MARK = `
<svg class="mark" viewBox="0 0 100 100" aria-hidden="true">
  <rect x="0.5" y="0.5" width="99" height="99" rx="22" class="mark-bg"/>
  <path class="mark-f" d="M31 20.5h35.5v11.5H42.5v13.5h21.5v11h-21.5v23H31z"/>
  <circle class="mark-dot" cx="71" cy="74.5" r="8.5"/>
</svg>`;

  window.FCPMark = function (el) {
    if (el && !el.firstElementChild) el.insertAdjacentHTML("afterbegin", MARK);
  };

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("[data-mark]").forEach(window.FCPMark);
  });
})();
