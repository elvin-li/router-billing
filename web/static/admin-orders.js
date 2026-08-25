// admin-orders.js — refund confirmation dialog on /admin/orders.
// Was an inline <script> + onclick attributes in admin_orders.html; the
// CSP (script-src 'self', no 'unsafe-inline') blocks those, so the
// dialog wiring lives here, keyed off data-* attributes.
(function () {
  'use strict';

  document.querySelectorAll('.js-refund-open').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var d = btn.dataset;
      document.getElementById('refundOrderNo').textContent = d.orderNo;
      document.getElementById('refundMac').textContent = d.mac;
      document.getElementById('refundDays').textContent = d.days;
      document.getElementById('refundAmt').textContent = d.amount;
      document.getElementById('refundOrderNoInput').value = d.orderNo;
      document.getElementById('refundConfirmInput').value = '';
      document.getElementById('refundDialog').showModal();
    });
  });
})();
