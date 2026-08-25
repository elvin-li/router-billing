// Live device list via SSE. Replaces the existing table tbody on each event.
// Falls back silently if EventSource is unavailable (very old browsers).
(function () {
  'use strict';
  if (!window.EventSource) return;

  const tbody = document.querySelector('table.data tbody');
  if (!tbody) return;

  function pill(text, cls) {
    return `<span class="pill ${cls}">${text}</span>`;
  }

  function statusCell(d) {
    let out = d.online ? pill('在线', 'active') : pill('离线', 'expired');
    out += ' ';
    if (d.active) out += pill('已授权', 'active');
    else if (d.known) out += pill('已过期', 'expired');
    else out += pill('未授权', 'pending');
    return out;
  }

  function escape(s) {
    return String(s || '').replace(/[&<>"]/g, c => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]
    ));
  }

  // The CSRF token from the cookie — SSE-rendered forms need it too.
  function csrfTok() {
    const m = document.cookie.match(/(?:^|; )rb_csrf=([^;]+)/);
    return m ? decodeURIComponent(m[1]) : '';
  }

  function render(devs) {
    if (!devs || devs.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">没有发现设备。让设备连接收费 SSID 后等待几秒…</td></tr>`;
      return;
    }
    const tok = csrfTok();
    tbody.innerHTML = devs.map(d => `
      <tr class="${(!d.active && d.online) ? 'highlight' : ''}">
        <td>
          <div class="mono">${escape(d.mac)}</div>
          ${d.hostname ? `<div style="font-size:12px;color:var(--text-soft);">${escape(d.hostname)}</div>` : ''}
        </td>
        <td class="mono">${escape(d.ip)}</td>
        <td>${statusCell(d)}</td>
        <td style="color:var(--text-soft);">${escape(d.last_seen_at)}</td>
        <td class="mono" style="color:var(--text-soft);">${escape(d.bytes_human || '')}</td>
        <td>${d.known ? escape(d.expires_at) : '<span style="color:var(--text-muted);">—</span>'}</td>
        <td class="row-actions">
          <form method="post" action="/admin/macs/extend">
            <input type="hidden" name="_csrf" value="${escape(tok)}">
            <input type="hidden" name="mac" value="${escape(d.mac)}">
            <select name="days" title="授权时长">
              <option value="30">30 天</option>
              <option value="365" selected>1 年</option>
              <option value="1825">5 年</option>
              <option value="3650">10 年</option>
            </select>
            <button class="btn primary tiny" type="submit">${d.active ? '续期' : '授权'}</button>
          </form>
          ${d.known ? `
          <form method="post" action="/admin/macs/delete" data-confirm="收回 ${escape(d.mac)} 的授权?">
            <input type="hidden" name="_csrf" value="${escape(tok)}">
            <input type="hidden" name="mac" value="${escape(d.mac)}">
            <button class="btn danger tiny" type="submit">收回</button>
          </form>` : ''}
        </td>
      </tr>
    `).join('');
  }

  const es = new EventSource('/admin/devices/stream');
  es.addEventListener('devices', (ev) => {
    try {
      render(JSON.parse(ev.data));
    } catch (e) {
      console.warn('devices stream parse', e);
    }
  });
  es.onerror = () => {
    // Don't spam — browser auto-reconnects.
    console.warn('devices stream error; reconnecting…');
  };
})();
