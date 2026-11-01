/* AI Guard: admin panel integration (alerts, nav badge, risk column on Teams/Users pages) */
(function () {
  "use strict";

  var root = (window.init && window.init.urlRoot) || "";
  var POLL_MS = 20000;
  var STORAGE_KEY = "aiguard:lastAlertId";

  function url(path) {
    return root + path;
  }

  function storageGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch (e) {
      return null;
    }
  }

  function storageSet(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch (e) {
      /* private mode */
    }
  }

  function getJSON(path) {
    return fetch(url(path), {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    }).then(function (r) {
      if (!r.ok) throw new Error(r.status);
      return r.json();
    });
  }

  function postJSON(path, body) {
    return fetch(url(path), {
      method: "POST",
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "CSRF-Token": (window.init && window.init.csrfNonce) || "",
      },
      body: JSON.stringify(body || {}),
    }).then(function (r) {
      return r.json();
    });
  }

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === "text") node.textContent = attrs[k];
      else if (k === "style") node.style.cssText = attrs[k];
      else node.setAttribute(k, attrs[k]);
    });
    (children || []).forEach(function (c) {
      if (c) node.appendChild(c);
    });
    return node;
  }

  function riskClass(score, threshold) {
    if (score >= threshold) return "badge-danger";
    if (score >= threshold / 2) return "badge-warning";
    if (score > 0) return "badge-success";
    return "badge-light";
  }

  /* ---------------- nav badge ---------------- */

  function navLink() {
    var links = document.querySelectorAll("a.nav-link");
    for (var i = 0; i < links.length; i++) {
      var href = (links[i].getAttribute("href") || "").replace(/\/+$/, "");
      if (/\/admin\/ai_guard$/.test(href)) return links[i];
    }
    return null;
  }

  function updateNavBadge(count) {
    var link = navLink();
    if (!link) return;
    var badge = link.querySelector(".aig-nav-badge");
    if (!count) {
      if (badge) badge.remove();
      return;
    }
    if (!badge) {
      badge = el("span", {
        class: "badge badge-pill badge-danger aig-nav-badge",
        style: "margin-left:4px",
      });
      link.appendChild(badge);
    }
    badge.textContent = count > 99 ? "99+" : String(count);
    badge.title = "New AI Guard alerts: " + count;
  }

  /* ---------------- toasts ---------------- */

  var container = null;

  function toastContainer() {
    if (!container) {
      container = el("div", {
        id: "aig-toasts",
        style:
          "position:fixed;right:16px;bottom:16px;z-index:2000;width:360px;max-width:calc(100vw - 32px);",
      });
      document.body.appendChild(container);
    }
    return container;
  }

  function showToast(ev) {
    var hide = ev.kind === "auto_hide";
    var color = hide ? "#dc3545" : ev.kind === "honeypot" ? "#dc3545" : "#ffc107";
    var close = el("button", {
      type: "button",
      class: "close",
      "aria-label": "Close",
      style: "margin-left:8px",
    });
    close.innerHTML = "&times;";
    var title = el("div", { style: "display:flex;align-items:center;" }, [
      el("strong", {
        text: (hide ? "🚫 " : "⚠️ ") + "AI Guard · " + ev.label,
        style: "flex:1",
      }),
      close,
    ]);
    var body = el("div", { style: "margin:4px 0 6px" }, [
      el("div", {}, [
        el("b", { text: ev.account_name }),
        document.createTextNode(
          " — risk " + Number(ev.score_after).toFixed(1) + "/10" +
            (ev.weight > 0 ? " (+" + Number(ev.weight).toFixed(1) + ")" : "")
        ),
      ]),
      el("small", { text: ev.summary, class: "text-muted" }),
    ]);
    var open = el("a", { href: ev.url, class: "btn btn-sm btn-outline-primary", text: "Open" });
    var ack = el("button", { type: "button", class: "btn btn-sm btn-outline-success", text: "Mark as read", style: "margin-left:6px" });
    var toast = el(
      "div",
      {
        class: "card shadow",
        role: "alert",
        style:
          "margin-top:10px;padding:10px 12px;border-left:5px solid " + color + ";background:#fff;color:#212529;",
      },
      [title, body, el("div", {}, [open, ack])]
    );
    function dismiss() {
      if (toast.parentNode) toast.parentNode.removeChild(toast);
    }
    close.addEventListener("click", dismiss);
    ack.addEventListener("click", function () {
      postJSON("/admin/ai_guard/api/alerts/ack", { ids: [ev.id] }).then(function (res) {
        if (res && res.success) updateNavBadge(res.unacked);
      });
      dismiss();
    });
    toastContainer().appendChild(toast);
    // Signals fade out on their own, a hidden account stays on screen until dismissed
    if (!hide) setTimeout(dismiss, 20000);
  }

  /* ---------------- polling ---------------- */

  function poll() {
    var stored = storageGet(STORAGE_KEY);
    var last = stored === null ? null : parseInt(stored, 10) || 0;
    var path = "/admin/ai_guard/api/alerts" + (last !== null ? "?after=" + last : "");
    getJSON(path)
      .then(function (res) {
        if (!res || !res.success) return;
        updateNavBadge(res.unacked);
        if (last === null || res.latest_id < last) {
          // First visit (or the database was reset): start from the newest event
          storageSet(STORAGE_KEY, String(res.latest_id));
          return;
        }
        var maxId = last;
        (res.data || []).forEach(function (ev) {
          showToast(ev);
          if (ev.id > maxId) maxId = ev.id;
        });
        storageSet(STORAGE_KEY, String(maxId));
      })
      .catch(function () {
        /* not an admin anymore or server unavailable */
      });
  }

  /* ---------------- Teams / Users pages ---------------- */

  function currentPath() {
    var p = window.location.pathname;
    if (root && p.indexOf(root) === 0) p = p.slice(root.length);
    return p.replace(/\/+$/, "");
  }

  function riskBadge(info, threshold, accountId, baseUrl) {
    var score = info ? Number(info.score) : 0;
    var badge = el("a", {
      class: "badge " + riskClass(score, threshold),
      href: info ? info.url : baseUrl,
      title: "AI risk score (threshold " + threshold + ")",
      text: score.toFixed(1),
      style: "font-size:90%;" + (score === 0 ? "border:1px solid #dee2e6;color:#6c757d;" : ""),
    });
    var wrap = el("span", {}, [badge]);
    if (info && info.whitelisted) {
      wrap.appendChild(document.createTextNode(" "));
      wrap.appendChild(el("span", { class: "badge badge-info", text: "trusted", title: "Trusted (AI Guard)" }));
    }
    if (info && info.shamed) {
      wrap.appendChild(document.createTextNode(" "));
      wrap.appendChild(el("span", { class: "badge badge-dark", text: "shame", title: "On the wall of shame (AI Guard)" }));
    } else if (info && info.auto_hidden) {
      wrap.appendChild(document.createTextNode(" "));
      wrap.appendChild(el("span", { class: "badge badge-dark", text: "AI", title: "Hidden by AI Guard" }));
    }
    return wrap;
  }

  function decorateListing(scores) {
    var table = document.getElementById("teamsboard");
    if (!table || table.querySelector(".aig-col")) return;
    var headRow = table.querySelector("thead tr");
    if (headRow) {
      var th = el("th", { class: "text-center px-1 aig-col" }, [el("b", { text: "AI Risk" })]);
      headRow.appendChild(th);
    }
    table.querySelectorAll("tbody tr[name]").forEach(function (tr) {
      var id = tr.getAttribute("name");
      var td = el("td", { class: "text-center aig-col" }, [
        riskBadge(scores.data[id], scores.threshold, id, scores.base_url),
      ]);
      tr.appendChild(td);
    });
  }

  function decorateDetail(scores, id) {
    var h1 = document.getElementById("team-id");
    if (!h1 || document.querySelector(".aig-detail")) return;
    var info = scores.data[id];
    var box = el("div", { class: "aig-detail text-center", style: "margin:6px 0 10px" }, [
      el("span", { class: "text-muted", text: "AI Risk: " }),
      riskBadge(info, scores.threshold, id, scores.base_url),
      document.createTextNode(" "),
      el("a", {
        href: info ? info.url : scores.base_url,
        class: "small",
        text: "details in AI Guard →",
        style: "margin-left:6px",
      }),
    ]);
    h1.parentNode.insertBefore(box, h1.nextSibling);
  }

  function decoratePages() {
    var path = currentPath();
    var m = path.match(/^\/admin\/(teams|users)(?:\/(\d+))?$/);
    if (!m) return;
    getJSON("/admin/ai_guard/api/scores")
      .then(function (scores) {
        if (!scores || !scores.success) return;
        if ((scores.mode === "teams") !== (m[1] === "teams")) return;
        if (m[2]) decorateDetail(scores, m[2]);
        else decorateListing(scores);
      })
      .catch(function () {});
  }

  function start() {
    decoratePages();
    poll();
    setInterval(poll, POLL_MS);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
