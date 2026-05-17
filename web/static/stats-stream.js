// Live stats updates for the admin dashboard. Subscribes to
// /admin/stats/stream (SSE) and patches the .stat-value cells in place.
(function () {
  'use strict';
  if (!window.EventSource) return;

  function nodeFor(metric) {
    return document.querySelector(`.stat svg.spark[data-metric="${metric}"]`)
      ?.closest('.stat')?.querySelector('.stat-value');
  }

  function fmtYuan(cents) {
    const y = (cents / 100).toFixed(2);
    return '¥' + y;
  }

  function update(s) {
    const map = {
      mac_total: () => String(s.total),
      mac_active: () => String(s.active),
      revenue_cents: () => fmtYuan(s.revenue_cents),
    };
    for (const k of Object.keys(map)) {
      const n = nodeFor(k);
      if (n && n.textContent !== map[k]()) {
        n.textContent = map[k]();
        n.style.transition = 'background 0.5s';
        n.style.background = 'rgba(99,102,241,0.15)';
        setTimeout(() => { n.style.background = ''; }, 600);
      }
    }
  }

  const es = new EventSource('/admin/stats/stream');
  es.addEventListener('stats', (ev) => {
    try { update(JSON.parse(ev.data)); } catch (_) {}
  });
  es.onerror = () => { /* browser auto-reconnects */ };
})();
