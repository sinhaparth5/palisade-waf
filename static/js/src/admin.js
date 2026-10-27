// Shared admin UI behaviour that used to live in inline <script> blocks and
// on*= attributes, moved here so the admin CSP can forbid inline script
// (issue #195). Everything is delegated on document so it survives HTMX swaps.

// ── Confirm modal (hx-confirm) ────────────────────────────────────────────────
(function () {
  var overlay   = document.getElementById('confirm-modal-overlay');
  if (!overlay) return;
  var msgEl     = document.getElementById('confirm-modal-message');
  var btnOk     = document.getElementById('confirm-modal-ok');
  var btnCancel = document.getElementById('confirm-modal-cancel');
  var _resolve  = null;

  function show(q) {
    msgEl.textContent = q;
    overlay.classList.remove('hidden');
    btnOk.focus();
    return new Promise(function (res) { _resolve = res; });
  }

  function hide()    { overlay.classList.add('hidden'); _resolve = null; }
  function confirm() { var r = _resolve; hide(); if (r) r(true);  }
  function cancel()  { var r = _resolve; hide(); if (r) r(false); }

  btnOk.addEventListener('click', confirm);
  btnCancel.addEventListener('click', cancel);
  overlay.addEventListener('click', function (e) { if (e.target === overlay) cancel(); });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('hidden')) cancel();
  });

  document.addEventListener('htmx:confirm', function (evt) {
    if (!evt.detail.question) return; // no hx-confirm on this element, let htmx proceed normally
    evt.preventDefault();
    show(evt.detail.question).then(function (ok) { if (ok) evt.detail.issueRequest(true); });
  });
})();

// ── Form resets after an HTMX request ─────────────────────────────────────────
// data-reset="success" resets only when the request succeeded; "always"
// resets either way.
document.addEventListener('htmx:afterRequest', function (e) {
  var form = e.detail.elt;
  var mode = form && form.dataset && form.dataset.reset;
  if (mode === 'always' || (mode === 'success' && e.detail.successful)) form.reset();
});

// ── Change handlers ───────────────────────────────────────────────────────────
document.addEventListener('change', function (e) {
  var t = e.target;

  // toggle_switch with Controls: show the controlled block while checked.
  if (t.dataset.controls) {
    var ctl = t.form && t.form.querySelector(t.dataset.controls);
    if (ctl) ctl.classList.toggle('hidden', !t.checked);
  }

  // Settings → Database connection: driver picker.
  if (t.id === 'dbconn_driver') {
    var v = t.value;
    var byId = function (id) { return document.getElementById(id); };
    byId('dbconn-external-fields').classList.toggle('hidden', v === 'sqlite');
    byId('dbconn-test-row').classList.toggle('hidden', v === 'sqlite');
    byId('dbconn-host-label').textContent = v === 'sqlite' ? 'Database file path' : 'Host';
    byId('dbconn_host').placeholder = v === 'sqlite' ? 'waf.db' : 'db.example.com, 172.18.0.5, or a Docker service name like db';
    byId('dbconn_port').placeholder = v === 'mysql' ? '3306' : '5432';
    byId('dbconn_sslmode_mysql').classList.toggle('hidden', v !== 'mysql');
    byId('dbconn_sslmode_mysql').disabled = (v !== 'mysql');
    byId('dbconn_sslmode_postgres').classList.toggle('hidden', v !== 'postgres');
    byId('dbconn_sslmode_postgres').disabled = (v !== 'postgres');
  }

  // Settings → Database connection: fields vs connection string.
  if (t.name === 'dbconn_mode') {
    var dsn = t.value === 'dsn';
    document.getElementById('dbconn-dsn-field').classList.toggle('hidden', !dsn);
    document.getElementById('dbconn-fields-group').classList.toggle('hidden', dsn);
  }

  // Certificates: a file input with data-fills loads the file into that
  // textarea, and names the cert from the filename if the field is empty.
  if (t.type === 'file' && t.dataset.fills) {
    var file = t.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function (ev) {
      var ta = document.getElementById(t.dataset.fills);
      if (ta) ta.value = ev.target.result;
      var nameField = t.dataset.names && document.getElementById(t.dataset.names);
      if (nameField && nameField.value.trim() === '') {
        nameField.value = file.name
          .replace(/^.*[/\\]/, '')
          .replace(/\.(pem|crt|cer|key)$/i, '')
          .replace(/[^a-zA-Z0-9._-]+/g, '-')
          .replace(/^-+|-+$/g, '');
      }
      t.value = ''; // so the same file can be re-selected
    };
    reader.readAsText(file);
  }
});

// Certificates: clear the error box once the form is edited again.
document.addEventListener('input', function (e) {
  if (e.target.form && e.target.form.id === 'cert-upload-form') {
    var err = document.getElementById('cert-error');
    if (err) err.textContent = '';
  }
});
