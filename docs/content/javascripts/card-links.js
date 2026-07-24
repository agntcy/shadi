/* Copyright SHADI Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* Grid card enhancements: single-link stretch targets. */
document$.subscribe(function () {
  document.querySelectorAll(".md-typeset .grid.cards > ul > li").forEach(function (li) {
    var links = li.querySelectorAll("a[href]");
    li.classList.toggle("card-single-link", links.length === 1);
  });
});
