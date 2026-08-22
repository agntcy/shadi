/* Open off-site links in a new tab site-wide (nav, content, footer). */
document$.subscribe(function () {
  document.querySelectorAll("a[href]").forEach(function (link) {
    var href = link.getAttribute("href");
    if (!href) {
      return;
    }

    var url;
    try {
      url = new URL(href, window.location.href);
    } catch (e) {
      return;
    }

    /* Allowlisted rather than denylisted: mailto:, tel:, javascript: and data:
       are all left alone without having to be named. */
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return;
    }

    if (url.origin === window.location.origin) {
      return;
    }

    link.setAttribute("target", "_blank");
    link.setAttribute("rel", "noopener noreferrer");
  });
});
