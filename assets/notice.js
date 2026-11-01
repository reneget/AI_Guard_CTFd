/* AI Guard: private notices for participants whose account was hidden */
(function () {
  "use strict";

  var init = window.init || {};
  if (!init.userId) return;

  var root = init.urlRoot || "";
  var POLL_MS = 60000;
  var queue = [];
  var seen = {};
  var modalOpen = false;
  var ticketUrl = null;

  function el(tag, style, text) {
    var node = document.createElement(tag);
    if (style) node.style.cssText = style;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function button(text, primary) {
    return el(
      primary ? "a" : "button",
      "display:inline-block;margin:0 0 0 8px;padding:8px 16px;border-radius:6px;font-size:15px;" +
        "cursor:pointer;text-decoration:none;border:1px solid " + (primary ? "#dc3545" : "#6c757d") + ";" +
        "background:" + (primary ? "#dc3545" : "transparent") + ";color:" + (primary ? "#fff" : "inherit") + ";",
      text
    );
  }

  function markRead(id) {
    return fetch(root + "/ai_guard/api/notice/" + id + "/read", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "CSRF-Token": init.csrfNonce || "",
      },
      body: "{}",
    }).catch(function () {});
  }

  function showNext() {
    if (modalOpen || !queue.length) return;
    var notice = queue.shift();
    modalOpen = true;

    var overlay = el(
      "div",
      "position:fixed;inset:0;z-index:100000;background:rgba(0,0,0,.6);display:flex;" +
        "align-items:center;justify-content:center;padding:16px;"
    );
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    var box = el(
      "div",
      "max-width:560px;width:100%;background:#fff;color:#212529;border-radius:10px;" +
        "border-top:6px solid #dc3545;box-shadow:0 10px 40px rgba(0,0,0,.4);padding:24px;" +
        "font-family:inherit;max-height:90vh;overflow:auto;"
    );
    box.appendChild(el("div", "font-size:20px;font-weight:700;margin-bottom:12px;", "🛡️ " + notice.title));
    box.appendChild(el("div", "white-space:pre-wrap;line-height:1.5;font-size:15px;margin-bottom:20px;", notice.content));

    var actions = el("div", "text-align:right;");
    var ok = button("OK", false);
    ok.type = "button";
    if (ticketUrl) {
      var ticket = button("Open a ticket", true);
      ticket.href = ticketUrl;
      ticket.target = "_blank";
      ticket.rel = "noopener noreferrer";
      actions.appendChild(ticket);
    }
    actions.appendChild(ok);
    box.appendChild(actions);
    overlay.appendChild(box);
    document.body.appendChild(overlay);
    ok.focus();

    ok.addEventListener("click", function () {
      markRead(notice.id);
      overlay.parentNode.removeChild(overlay);
      modalOpen = false;
      showNext();
    });
  }

  function banner(text) {
    var node = document.getElementById("aig-banner");
    // Rebuild when the status changes (e.g. a hidden account is put on the wall of shame)
    if (node && node.getAttribute("data-text") === text) return;
    if (node) node.parentNode.removeChild(node);
    if (!text) return;
    node = el(
      "div",
      "background:#dc3545;color:#fff;text-align:center;padding:10px 16px;font-size:15px;" +
        "position:relative;z-index:1030;",
      "🛡️ " + text
    );
    node.id = "aig-banner";
    node.setAttribute("data-text", text);
    if (ticketUrl) {
      var link = el(
        "a",
        "color:#fff;font-weight:700;text-decoration:underline;margin-left:10px;",
        "Open a ticket →"
      );
      link.href = ticketUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      node.appendChild(link);
    }
    // Inside <main> the banner stays below the theme's (possibly fixed) navbar
    var parent = document.querySelector("main") || document.body;
    parent.insertBefore(node, parent.firstChild);
  }

  function check() {
    fetch(root + "/ai_guard/api/notice", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (res) {
        var data = res && res.success ? res.data : null;
        if (!data) {
          banner(null);
          return;
        }
        ticketUrl = data.ticket_url;
        banner(data.hidden ? data.banner : null);
        (data.notices || []).forEach(function (n) {
          if (!seen[n.id]) {
            seen[n.id] = true;
            queue.push(n);
          }
        });
        showNext();
      })
      .catch(function () {});
  }

  function start() {
    check();
    setInterval(check, POLL_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
