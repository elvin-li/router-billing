// Tiny SVG sparkline for /admin/macs dashboard stats cards.
// Fetches /admin/charts.json (last 30 days) and draws one line per
// <svg class="spark" data-metric="...">. Zero deps, no canvas.
(function () {
  'use strict';
  const sparks = document.querySelectorAll('svg.spark');
  if (!sparks.length) return;

  fetch('/admin/charts.json', { credentials: 'same-origin' })
    .then(r => r.ok ? r.json() : null)
    .then(data => {
      if (!data || !Array.isArray(data.rows) || data.rows.length === 0) return;
      sparks.forEach(svg => draw(svg, data.rows, svg.dataset.metric));
    })
    .catch(() => { /* ignore */ });

  function draw(svg, rows, metric) {
    const w = +svg.getAttribute('width');
    const h = +svg.getAttribute('height');
    const pad = 2;
    const vals = rows.map(r => +r[metric] || 0);
    const min = Math.min.apply(null, vals);
    const max = Math.max.apply(null, vals);
    const range = (max - min) || 1;

    const stepX = (w - 2 * pad) / Math.max(vals.length - 1, 1);
    const pts = vals.map((v, i) => {
      const x = pad + i * stepX;
      const y = h - pad - ((v - min) / range) * (h - 2 * pad);
      return [x, y];
    });

    const ns = 'http://www.w3.org/2000/svg';

    // Filled area under line
    const areaD = `M ${pts[0][0]} ${h - pad} ` +
      pts.map(p => `L ${p[0]} ${p[1]}`).join(' ') +
      ` L ${pts[pts.length - 1][0]} ${h - pad} Z`;
    const area = document.createElementNS(ns, 'path');
    area.setAttribute('d', areaD);
    area.setAttribute('fill', 'currentColor');
    area.setAttribute('opacity', '0.12');
    svg.appendChild(area);

    // Line
    const lineD = 'M ' + pts.map(p => `${p[0].toFixed(1)} ${p[1].toFixed(1)}`).join(' L ');
    const line = document.createElementNS(ns, 'path');
    line.setAttribute('d', lineD);
    line.setAttribute('fill', 'none');
    line.setAttribute('stroke', 'currentColor');
    line.setAttribute('stroke-width', '1.5');
    line.setAttribute('stroke-linejoin', 'round');
    line.setAttribute('stroke-linecap', 'round');
    svg.appendChild(line);

    // Last dot
    const last = pts[pts.length - 1];
    const dot = document.createElementNS(ns, 'circle');
    dot.setAttribute('cx', last[0]);
    dot.setAttribute('cy', last[1]);
    dot.setAttribute('r', '2');
    dot.setAttribute('fill', 'currentColor');
    svg.appendChild(dot);
  }
})();
