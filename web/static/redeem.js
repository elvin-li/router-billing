// redeem.js — voucher-code input formatting on /redeem.
// Was an inline <script> in redeem.html; the CSP (script-src 'self',
// no 'unsafe-inline') blocks inline scripts, so it lives here now.
(function () {
  'use strict';
  // Auto-format the code input as 4-4-4 grouped, uppercase, alphabet-only.
  var inp = document.getElementById('code-input');
  if (!inp) return;
  inp.addEventListener('input', function () {
    var v = inp.value.toUpperCase().replace(/[^A-Z2-9]/g, '');
    v = v.replace(/[01OIL]/g, '');
    if (v.length > 12) v = v.slice(0, 12);
    var parts = [];
    for (var i = 0; i < v.length; i += 4) parts.push(v.slice(i, i + 4));
    inp.value = parts.join('-');
  });
})();
