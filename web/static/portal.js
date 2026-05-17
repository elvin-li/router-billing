// Portal client. Talks to /api/pay/* on the same host.
(function () {
  'use strict';

  const $ = (sel) => document.querySelector(sel);
  const modal      = $('#qr-modal');
  const qrImage    = $('#qr-image');
  const qrAmount   = $('#qr-amount');
  const qrStatus   = $('#qr-status');
  const qrTitle    = $('#qr-title');
  const qrClose    = $('#qr-close');
  const macInput   = $('#mac-input');

  let pollTimer = null;

  function show(msg) { qrStatus.textContent = msg; qrStatus.classList.remove('paid'); }
  function paid(msg) { qrStatus.textContent = msg; qrStatus.classList.add('paid'); }

  function getMAC() {
    const v = (macInput && macInput.value || '').trim().toUpperCase();
    return v;
  }

  function getPlan() {
    const r = document.querySelector('input[name="plan"]:checked');
    return r ? r.value : '';
  }

  async function startPay(provider) {
    const mac = getMAC();
    const plan = getPlan();
    if (!mac) { alert('请填入 MAC 地址'); return; }
    if (!plan) { alert('请选择套餐'); return; }

    qrTitle.textContent  = provider === 'wechat' ? '微信扫码支付' : '支付宝扫码';
    qrAmount.textContent = '加载中…';
    qrImage.removeAttribute('src');
    show('正在生成订单…');
    modal.classList.remove('hidden');

    try {
      const r = await fetch('/api/pay/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mac, plan, provider })
      });
      const data = await r.json();
      if (!r.ok) { show('下单失败：' + (data.error || r.status)); return; }
      qrAmount.textContent = '¥' + data.amount;
      qrImage.src = data.qr_png;
      show('请扫码支付…');
      startPolling(data.order_no, mac);
    } catch (e) {
      show('网络错误：' + e.message);
    }
  }

  // Long-poll via /api/pay/wait — the server holds the connection up to 60s
  // and returns instantly when the order goes paid. Loop until paid or user
  // closes the modal. Falls back to 2s short-poll on /api/pay/status if /wait
  // is somehow unavailable.
  let waitAbort = null;
  async function startPolling(orderNo, mac) {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
    if (waitAbort) waitAbort.abort();
    waitAbort = new AbortController();

    const deadline = Date.now() + 8 * 60 * 1000; // total cap: 8 minutes
    while (Date.now() < deadline) {
      try {
        const r = await fetch('/api/pay/wait?order_no=' + encodeURIComponent(orderNo),
                              { signal: waitAbort.signal });
        if (!r.ok) {
          // /wait not supported? fall back.
          fallbackPoll(orderNo, mac);
          return;
        }
        const data = await r.json();
        if (data.status === 'paid') {
          paid('✓ 支付成功，3 秒后跳转…');
          setTimeout(() => {
            window.location = '/pay/success?mac=' + encodeURIComponent(mac);
          }, 3000);
          return;
        }
        // status=pending → re-issue the long-poll.
      } catch (e) {
        if (e.name === 'AbortError') return;
        // network blip; back off briefly
        await new Promise(r => setTimeout(r, 1500));
      }
    }
    show('支付超时，请关闭重试');
  }

  function fallbackPoll(orderNo, mac) {
    let tries = 0;
    pollTimer = setInterval(async () => {
      tries++;
      try {
        const r = await fetch('/api/pay/status?order_no=' + encodeURIComponent(orderNo));
        if (!r.ok) return;
        const data = await r.json();
        if (data.status === 'paid') {
          clearInterval(pollTimer);
          paid('✓ 支付成功，3 秒后跳转…');
          setTimeout(() => {
            window.location = '/pay/success?mac=' + encodeURIComponent(mac);
          }, 3000);
        }
      } catch (_) {}
      if (tries > 240) { clearInterval(pollTimer); show('支付超时，请关闭重试'); }
    }, 2000);
  }

  document.querySelectorAll('button[data-provider]').forEach(b => {
    b.addEventListener('click', () => startPay(b.getAttribute('data-provider')));
  });

  qrClose && qrClose.addEventListener('click', () => {
    modal.classList.add('hidden');
    if (pollTimer) clearInterval(pollTimer);
    if (waitAbort) waitAbort.abort();
  });

  // Format mac input as user types
  if (macInput && !macInput.value) {
    macInput.addEventListener('input', () => {
      let v = macInput.value.toUpperCase().replace(/[^0-9A-F]/g, '');
      if (v.length > 12) v = v.slice(0, 12);
      const parts = [];
      for (let i = 0; i < v.length; i += 2) parts.push(v.slice(i, i + 2));
      macInput.value = parts.join(':');
    });
  }
})();
