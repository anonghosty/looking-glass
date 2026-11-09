/* Display quality, shared by the intro page and both platforms (loaded in <head>, before anything is drawn).

   Full: every effect. Lite: for smart TVs and older computers (flat map, no blur or glow, fewer animated items).
   Auto (default): Lite on TV browsers and very weak devices, and after the map measured slow drawing on this device.
   The choice is remembered per device (localStorage) and applies to every page; ?perf=auto|full|lite sets it from
   the address. Any element group with class "perf-seg" and buttons data-perf="auto|full|lite" switches it, and
   elements with class "perf-hint" show what is in use. Changing it reloads the page so every setting applies. */
(function () {
  "use strict";
  var KEY = "lg.perf", AUTO_KEY = "lg.perfAutoLite", CHOICES = ["auto", "full", "lite"];
  function get(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function set(k, v) { try { if (v === null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch (e) { /* private mode */ } }

  var param = new URLSearchParams(location.search).get("perf");
  if (CHOICES.indexOf(param) >= 0) set(KEY, param);
  var choice = CHOICES.indexOf(get(KEY)) >= 0 ? get(KEY) : "auto";
  var ua = navigator.userAgent || "";
  var isTV = /SMART-?TV|SmartTV|Tizen|Web0S|webOS|NetCast|HbbTV|BRAVIA|Android TV|GoogleTV|AFT[A-Z]|CrKey|Roku|VIDAA|PhilipsTV|Viera|Opera TV|TV Safari|\bTV\b/i.test(ua);
  var weak = (navigator.hardwareConcurrency || 8) <= 2 || (navigator.deviceMemory || 8) <= 2;
  var reason = isTV ? "a TV browser" : weak ? "a low-power device" : get(AUTO_KEY) ? "slow drawing measured earlier on this device" : "";
  var lite = choice === "lite" || (choice === "auto" && !!reason);
  document.documentElement.classList.toggle("lite", lite);

  function hint(liveLite) {
    var on = liveLite === undefined ? lite : liveLite;
    var why = choice === "auto" ? (on ? " (chosen automatically: " + (reason || "slow drawing measured on this device") + ")" : " (chosen automatically)") : "";
    return "Now using " + (on ? "Lite" : "Full") + " display" + why + ".";
  }
  function render(liveLite) {
    var text = hint(liveLite), i, j, segs = document.querySelectorAll(".perf-seg"), hints = document.querySelectorAll(".perf-hint");
    for (i = 0; i < segs.length; i++) {
      segs[i].title = text;
      var bs = segs[i].querySelectorAll("[data-perf]");
      for (j = 0; j < bs.length; j++) bs[j].setAttribute("aria-pressed", String(bs[j].getAttribute("data-perf") === choice));
    }
    for (i = 0; i < hints.length; i++) hints[i].textContent = text;
  }
  function choose(v) {
    if (CHOICES.indexOf(v) < 0 || v === choice) return;
    set(KEY, v);
    if (v !== "lite") set(AUTO_KEY, null);          // Auto / Full: measure this device again
    var u = new URL(location.href);
    u.searchParams.delete("perf");
    var intro = document.getElementById("intro");   // stay on the intro page if that is where it was changed
    if (intro && !intro.hidden) u.searchParams.set("intro", "1");
    location.replace(u.toString());
  }
  document.addEventListener("click", function (e) {
    var b = e.target && e.target.closest ? e.target.closest(".perf-seg [data-perf]") : null;
    if (b) { e.preventDefault(); choose(b.getAttribute("data-perf")); }
  });
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { render(); });
  else render();

  window.LGDisplay = { KEY: KEY, AUTO_KEY: AUTO_KEY, choice: choice, lite: lite, reason: reason, isTV: isTV, weak: weak,
                       render: render, hint: hint, choose: choose,
                       markSlow: function () { set(AUTO_KEY, "1"); } };
})();
