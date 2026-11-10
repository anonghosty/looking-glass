/* The film players (mkdocs_hooks.py draws them): YouTube loads only when the reader presses play or a chapter, from
   the privacy-enhanced youtube-nocookie.com; a chapter button (re)starts the film at its time. */
(function () {
  "use strict";
  function play(fig, t) {
    var id = fig.getAttribute("data-yt");
    var start = t == null ? parseInt(fig.getAttribute("data-start") || "0", 10) : t;
    var src = "https://www.youtube-nocookie.com/embed/" + encodeURIComponent(id) +
      "?autoplay=1&rel=0&playsinline=1&cc_load_policy=1&start=" + start;
    var frame = fig.querySelector(".lg-film-frame");
    var ifr = frame.querySelector("iframe");
    if (!ifr) {
      ifr = document.createElement("iframe");
      ifr.title = fig.querySelector(".lg-film-title").textContent;
      ifr.allow = "autoplay; encrypted-media; picture-in-picture; fullscreen";
      ifr.allowFullscreen = true;
      ifr.referrerPolicy = "strict-origin-when-cross-origin";
      frame.replaceChildren(ifr);
    }
    ifr.src = src;
    fig.classList.add("is-playing");
    fig.querySelectorAll(".lg-film-ch").forEach(function (b) {
      b.classList.toggle("is-on", parseInt(b.getAttribute("data-t"), 10) === start);
    });
  }
  function wire(root) {
    root.querySelectorAll("figure.lg-film").forEach(function (fig) {
      if (fig.dataset.wired) return;
      fig.dataset.wired = "1";
      var poster = fig.querySelector(".lg-film-poster");
      if (poster) poster.addEventListener("click", function () { play(fig); });
      fig.querySelectorAll(".lg-film-ch").forEach(function (b) {
        b.addEventListener("click", function () {
          play(fig, parseInt(b.getAttribute("data-t"), 10));
          var frame = fig.querySelector(".lg-film-frame");
          if (frame.getBoundingClientRect().top < 0) frame.scrollIntoView({ behavior: "smooth", block: "start" });
        });
      });
    });
  }
  if (window.document$ && typeof window.document$.subscribe === "function") {
    window.document$.subscribe(function () { wire(document); });      // Material's page loads
  } else if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", function () { wire(document); });
  } else {
    wire(document);
  }
})();
