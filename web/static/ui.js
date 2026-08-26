// ui.js — CSP-safe replacements for inline event handlers.
//
// The site ships `Content-Security-Policy: script-src 'self'` (no
// 'unsafe-inline'), which makes browsers refuse BOTH inline <script>
// blocks and on*="" attributes. Every template behavior therefore hangs
// off data-* attributes wired up by the delegated listeners below.
// Delegation (document-level listeners) also covers content injected
// later via innerHTML (e.g. the devices SSE stream re-rendering rows).
//
//   data-confirm="msg"        on a <form>: confirm() before submitting.
//   data-confirm="msg"        on a button/link: confirm() before the click
//                             proceeds (covers submit buttons that need a
//                             different message per button).
//   data-print                on a button: window.print().
//   data-dialog-close="id"    on a button: close the <dialog id="id">.
//
// Literal "\n" sequences in data-confirm values become real newlines so
// multi-line confirmation prompts survive the trip through an HTML
// attribute.
(function () {
  'use strict';

  function confirmText(el) {
    return el.getAttribute('data-confirm').replace(/\\n/g, '\n');
  }

  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (f && f.hasAttribute && f.hasAttribute('data-confirm') && !window.confirm(confirmText(f))) {
      e.preventDefault();
    }
  });

  document.addEventListener('click', function (e) {
    if (!e.target || !e.target.closest) return;
    var el = e.target.closest('[data-confirm], [data-print], [data-dialog-close]');
    if (!el || el.tagName === 'FORM') return;
    if (el.hasAttribute('data-confirm') && !window.confirm(confirmText(el))) {
      e.preventDefault();
      e.stopPropagation();
      return;
    }
    if (el.hasAttribute('data-print')) {
      e.preventDefault();
      window.print();
      return;
    }
    var dlg = el.getAttribute('data-dialog-close');
    if (dlg) {
      var d = document.getElementById(dlg);
      if (d && d.close) d.close();
    }
  });
})();
