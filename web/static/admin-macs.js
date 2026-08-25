// admin-macs.js — bulk-select toolbar on /admin/macs.
// Was an inline <script> in admin_macs.html; the CSP (script-src 'self',
// no 'unsafe-inline') blocks inline scripts, so it lives here now.
(function () {
  'use strict';

  var bar = document.getElementById('bulk-bar');
  if (!bar) return;

  function picked() {
    return Array.prototype.slice.call(document.querySelectorAll('.bulk-pick:checked'));
  }

  function refreshBulk() {
    var n = picked().length;
    document.getElementById('bulk-count').textContent = n;
    bar.style.display = n > 0 ? 'flex' : 'none';
  }

  var all = document.getElementById('bulk-all');
  if (all) {
    all.addEventListener('change', function () {
      document.querySelectorAll('.bulk-pick').forEach(function (c) { c.checked = all.checked; });
      refreshBulk();
    });
  }
  document.querySelectorAll('.bulk-pick').forEach(function (c) {
    c.addEventListener('change', refreshBulk);
  });

  function submitBulk(action) {
    var rows = picked();
    if (rows.length === 0) { alert('请先勾选 MAC'); return; }
    if (action === 'extend') {
      var d = parseInt(document.getElementById('bulk-days').value, 10);
      if (!d || d < 1) { alert('请填入续费天数'); return; }
    }
    if (!confirm('对 ' + rows.length + ' 个 MAC 执行「' + (action === 'delete' ? '删除' : '续费') + '」？')) return;
    // Build + submit a transient form (no HTML5 nesting issues).
    var csrf = document.cookie.match(/(?:^|; )rb_csrf=([^;]+)/);
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/admin/macs/bulk';
    form.style.display = 'none';
    var add = function (n, v) {
      var i = document.createElement('input');
      i.name = n; i.value = v;
      form.appendChild(i);
    };
    add('_csrf', csrf ? decodeURIComponent(csrf[1]) : '');
    add('action', action);
    if (action === 'extend') add('days', document.getElementById('bulk-days').value);
    rows.forEach(function (p) { add('mac', p.value); });
    document.body.appendChild(form);
    form.submit();
  }

  var ext = document.getElementById('bulk-extend');
  var del = document.getElementById('bulk-delete');
  if (ext) ext.addEventListener('click', function () { submitBulk('extend'); });
  if (del) del.addEventListener('click', function () { submitBulk('delete'); });
})();
