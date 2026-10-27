// Login page behaviour (2FA auto-submit, passkey sign-in, password reveal),
// external so the admin CSP can forbid inline script (issue #195).
// Submit the 2FA form as soon as a 6-digit code is in (typed, pasted or
// autofilled); backup codes are 8 characters, so they still need Verify.
(function () {
  var code = document.getElementById('login-code');
  if (!code) return;
  code.addEventListener('input', function () {
    if (/^\d{6}$/.test(code.value.replace(/\s/g, ''))) {
      code.readOnly = true;
      code.form.requestSubmit ? code.form.requestSubmit() : code.form.submit();
    }
  });
})();
(function () {
  var pkBtn = document.getElementById('pk-login-btn');
  if (!pkBtn) return;
  var adminPath = document.body.dataset.adminPath;
  var statusEl = document.getElementById('pk-login-status');

  function b64urlToBuf(b64url) {
    var pad = '='.repeat((4 - (b64url.length % 4)) % 4);
    var b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
    var str = atob(b64);
    var buf = new Uint8Array(str.length);
    for (var i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf.buffer;
  }
  function bufToB64url(buf) {
    var bytes = new Uint8Array(buf);
    var str = '';
    for (var i = 0; i < bytes.byteLength; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function setStatus(msg, isError) {
    if (!statusEl) return;
    statusEl.textContent = msg;
    statusEl.className = 'mt-2 text-xs ' + (isError ? 'text-red-600' : 'text-slate-500');
  }

  pkBtn.addEventListener('click', function () {
    setStatus('Waiting for your passkey…', false);
    fetch(adminPath + '/login/webauthn/begin', { method: 'POST', credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (opts) {
        if (opts.error) throw new Error(opts.error);
        var pk = opts.publicKey;
        pk.challenge = b64urlToBuf(pk.challenge);
        (pk.allowCredentials || []).forEach(function (c) { c.id = b64urlToBuf(c.id); });
        return navigator.credentials.get({ publicKey: pk });
      })
      .then(function (cred) {
        var body = {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            authenticatorData: bufToB64url(cred.response.authenticatorData),
            clientDataJSON: bufToB64url(cred.response.clientDataJSON),
            signature: bufToB64url(cred.response.signature)
          }
        };
        if (cred.response.userHandle) {
          body.response.userHandle = bufToB64url(cred.response.userHandle);
        }
        return fetch(adminPath + '/login/webauthn/finish', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body)
        });
      })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (j.redirect) {
          window.location.href = j.redirect;
          return;
        }
        throw new Error(j.error || 'Passkey sign-in failed.');
      })
      .catch(function (err) {
        setStatus(err.message || 'Passkey sign-in failed.', true);
      });
  });
})();

(function () {
  var toggle  = document.getElementById('pw-toggle');
  var input   = document.getElementById('login-password');
  var iconOff = document.getElementById('pw-icon-off');
  var iconOn  = document.getElementById('pw-icon-on');
  if (!toggle) return;
  toggle.addEventListener('click', function () {
    var hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    iconOff.classList.toggle('hidden', hidden);
    iconOn.classList.toggle('hidden', !hidden);
    toggle.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
    toggle.setAttribute('aria-pressed', hidden ? 'true' : 'false');
  });
})();
