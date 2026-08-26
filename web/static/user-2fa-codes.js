// user-2fa-codes.js — "copy all" for the one-time backup codes page.
// Was an inline <script> in user_2fa_codes.html; the CSP (script-src
// 'self', no 'unsafe-inline') blocks inline scripts, so it lives here.
(function () {
  'use strict';
  var btn = document.getElementById('copy-codes');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var codes = Array.prototype.map.call(
      document.querySelectorAll('.codes-grid code'),
      function (el) { return el.textContent; }
    ).join('\n');
    var done = function () { alert('已复制到剪贴板'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(codes).then(done).catch(function () { fallback(codes); done(); });
    } else {
      fallback(codes);
      done();
    }
    function fallback(text) {
      // Fallback for non-https / unsupported browsers
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand('copy'); ta.remove();
    }
  });
})();
