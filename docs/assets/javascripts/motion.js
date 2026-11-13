/* The platform's motion on the documentation site: what is below the fold rises into view as the reader scrolls
   (sections, cards, films, tables, code), cards and steps one after another. The load animations are CSS only
   (looking-glass.css), so a page is never left hidden if this script does not run; and nothing moves for readers
   who ask their system for reduced motion. */
(function () {
  "use strict";
  if (!("IntersectionObserver" in window) || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  var SEL = [
    ".md-typeset h2", ".md-typeset .grid.cards > ul > li", ".md-typeset figure.lg-film", ".md-typeset .lg-pair",
    ".md-typeset .lg-steps ol > li", ".md-typeset table:not([class])", ".md-typeset .admonition", ".md-typeset details",
    ".md-typeset .highlight", ".md-typeset p > img", ".md-typeset blockquote"
  ].join(", ");
  var STAGGER = ".grid.cards > ul > li, .lg-steps ol > li, .lg-films > figure";

  function wire() {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.setAttribute("data-lg-in", ""); io.unobserve(e.target); }
      });
    }, { rootMargin: "0px 0px -6% 0px", threshold: 0.06 });
    var fold = window.innerHeight * 0.92, count = new Map();
    document.querySelectorAll(SEL).forEach(function (el) {
      if (el.hasAttribute("data-lg-reveal") || el.closest(".lg-hero")) return;
      if (el.getBoundingClientRect().top < fold) return;          // already on screen: the page's own fade-in shows it
      // an attribute, not a class: Material and this site style tables as table:not([class]), so a class would strip them
      el.setAttribute("data-lg-reveal", "");
      if (el.matches(STAGGER)) {
        var i = count.get(el.parentElement) || 0;
        count.set(el.parentElement, i + 1);
        el.style.setProperty("--lg-d", Math.min(i, 6) * 0.08 + "s");
      }
      io.observe(el);
    });
  }
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(wire);                               // Material's page loads
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
