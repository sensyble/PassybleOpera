// Local test site for the end-to-end tests, served on http://<sub>.example.localhost:<port> (Chromium
// resolves every *.localhost name to the loopback address), plus the mock agent's endpoint at POST /__agent.
// Every scenario has /s/<id>/login, which answers 303 to its 2FA page unless the scenario is an SPA.
import http from 'node:http';

const CSS = `body{font:15px system-ui,sans-serif;margin:40px}form,.box{max-width:420px}
label{display:block;margin:10px 0 4px}input{font:inherit;padding:8px;width:320px;box-sizing:border-box}
.split input{width:44px;text-align:center;margin-right:6px}button{margin-top:12px;padding:8px 16px}`;

function page(title, body, script = '') {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>${CSS}</style></head>
<body>${body}${script ? `<script>${script}</script>` : ''}</body></html>`;
}

const LOGIN_FORM = (action) => `<form method="post" action="${action}" id="login">
<h1>Sign in</h1>
<label for="email">Email</label><input type="email" id="email" name="email" autocomplete="username">
<label for="password">Password</label><input type="password" id="password" name="password" autocomplete="current-password">
<button type="submit">Sign in</button></form>`;

// A sign-up form (draft.e2e.mjs).
const SIGNUP_FORM = `<form method="post" action="/done" id="signup">
<h1>Create your account</h1>
<label for="email">Email</label><input type="email" id="email" name="email" autocomplete="email">
<label for="password">Password</label><input type="password" id="password" name="password" autocomplete="new-password">
<label for="confirm">Confirm password</label><input type="password" id="confirm" name="confirm">
<label for="bio">About you</label><input type="text" id="bio" name="bio">
<button type="submit">Create account</button></form>`;

const otpForm = (heading, field, { intro = 'Open your authenticator app and enter the code.', button = 'Verify' } = {}) =>
  `<form method="post" action="/done" id="otp-form"><h1>${heading}</h1><p>${intro}</p>${field}
<button type="submit">${button}</button></form>`;

// React-style controlled input: the instance `value` setter feeds a tracker, and a re-render writes
// the component state back; a value set without a real input event (as React sees it) is lost.
const CONTROLLED = `(() => {
  const el = document.getElementById('code');
  const proto = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  let state = ''; let tracked = '';
  Object.defineProperty(el, 'value', { configurable: true,
    get() { return proto.get.call(this); },
    set(v) { tracked = String(v); proto.set.call(this, v); } });
  const render = () => { proto.set.call(el, state); document.getElementById('state').textContent = state; };
  el.addEventListener('input', () => { const cur = proto.get.call(el); if (cur !== tracked) { tracked = cur; state = cur; render(); } });
  setInterval(render, 200);
})();`;

// Six one-digit boxes that move focus along, like most "code" widgets; the joined code goes to #state.
const SPLIT = `(() => {
  const boxes = [...document.querySelectorAll('.split input')];
  const sync = () => { document.getElementById('state').textContent = boxes.map((b) => b.value).join(''); };
  boxes.forEach((b, i) => b.addEventListener('input', () => {
    b.value = b.value.replace(/\\D/g, '').slice(-1);
    if (b.value && boxes[i + 1]) boxes[i + 1].focus();
    sync();
  }));
})();`;

const SPLIT_HTML = `<div class="split">${Array.from({ length: 6 }, (_, i) =>
  `<input type="text" inputmode="numeric" maxlength="1" aria-label="Digit ${i + 1}" autocomplete="off">`).join('')}</div>
<p>Code: <span id="state"></span></p>`;

// SPA sign-in: the form is sent with fetch and the 2FA field replaces it in the same document.
const spa = (otpHtml, { push = '', delay = 400 } = {}) => `(() => {
  const form = document.getElementById('login');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await fetch(location.pathname, { method: 'POST', body: new URLSearchParams(new FormData(form)) });
    setTimeout(() => {
      ${push ? `history.pushState({}, '', ${JSON.stringify(push)});` : ''}
      const box = document.createElement('div');
      box.className = 'box';
      box.innerHTML = ${JSON.stringify(otpHtml)};
      form.replaceWith(box);
    }, ${delay});
  });
})();`;

/**
 * Scenarios. `twofa`: path of the 2FA page on `twofaHost` (default: the login host); `html`: its
 * body; `script`: its script; `spa`: script for the login page instead (no 2FA page);
 * `field`: selector of the code field (or `state`: selector whose text must become the code);
 * `signsIn`: no 2FA step, the sign-in goes to /s/<id>/home (`html`).
 */
export const SCENARIOS = {
  // (a) separate 2FA page, autocomplete="one-time-code"
  a: { html: otpForm('Two-factor authentication', '<label for="c">Authentication code</label><input id="c" name="code" autocomplete="one-time-code" inputmode="numeric">'), field: '#c' },
  // (a2) separate 2FA page whose field is rendered by script after a second
  a2: { html: '<div id="root"><p>Loading…</p></div>', script: `setTimeout(() => { document.getElementById('root').innerHTML = ${JSON.stringify(otpForm('Verify it’s you', '<input id="c" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code">'))}; }, 1200);`, field: '#c' },
  // (b) no autocomplete: names, types and lengths
  'b-otp': { html: otpForm('Two-step verification', '<input id="c" name="otp" type="text">'), field: '#c' },
  'b-code': { html: otpForm('Enter code', '<input id="c" name="code" type="tel" maxlength="6">', { intro: 'We need to make sure it’s you.' }), field: '#c' },
  'b-totp': { html: otpForm('Security check', '<input id="totp" type="number" placeholder="123456">'), field: '#totp' },
  'b-verification': { html: otpForm('Verification', '<input id="c" name="verification_code" type="text">'), field: '#c' },
  'b-mfa': { html: otpForm('Sign in', '<input id="c" name="mfa_code" inputmode="numeric" type="text">'), field: '#c' },
  'b-numeric': { html: `<h1>Two-factor authentication</h1><p>Enter the 6-digit code from your authenticator app.</p><form method="post" action="/done"><input id="c" type="text" inputmode="numeric" maxlength="6" autocomplete="off"><button>Continue</button></form>`, field: '#c' },
  'b-lone': { html: `<form method="post" action="/done"><h1>2-Step Verification</h1><p>Enter the code shown in your authenticator app</p><input id="c" name="response" type="text"><button>Next</button></form>`, field: '#c' },
  // (c) six one-digit boxes
  c: { html: `<form method="post" action="/done"><h1>Enter your verification code</h1>${SPLIT_HTML}<button>Verify</button></form>`, script: SPLIT, state: '#state' },
  // (d) SPA: the 2FA field replaces the sign-in form after an XHR, no navigation
  d: { spa: spa(otpForm('Two-factor authentication', '<input id="c" name="otp" autocomplete="one-time-code">')), field: '#c' },
  // (d2) SPA with history.pushState to /verify
  d2: { spa: spa(otpForm('Two-factor authentication', '<input id="c" name="code" inputmode="numeric" maxlength="6">'), { push: '/s/d2/verify' }), field: '#c' },
  // (e) 2FA on another subdomain of the same site
  e: { twofaHost: 'auth', html: otpForm('Two-factor authentication', '<input id="c" name="otp_code" inputmode="numeric">'), field: '#c' },
  // (f) 2FA field inside a same-origin iframe
  f: { html: '<h1>Verify</h1><iframe id="frame" src="/frame/otp" style="width:480px;height:220px;border:0"></iframe>', frame: '#frame', field: '#c' },
  // (g) look-alikes of well-known sites
  github: { html: otpForm('Two-factor authentication', '<label for="app_totp">Authentication code</label><input type="text" name="app_otp" id="app_totp" class="form-control input-block" autocomplete="one-time-code" inputmode="numeric" pattern="([0-9]{6})|([0-9a-fA-F]{5}-?[0-9a-fA-F]{5})" placeholder="XXXXXX" aria-describedby="totp-hint">'), field: '#app_totp' },
  google: { html: `<form method="post" action="/done"><h1>2-Step Verification</h1><p>Get a verification code from the <b>Google Authenticator</b> app</p><input type="tel" name="totpPin" id="totpPin" autocomplete="off" pattern="[0-9 ]*" aria-label="Enter code"><button>Next</button></form>`, field: '#totpPin' },
  microsoft: { spa: spa(`<h1>Enter code</h1><p>Enter the code displayed in the authenticator app on your mobile device</p><input name="otc" type="tel" id="idTxtBx_SAOTCC_OTC" maxlength="6" class="form-control" aria-label="Code" placeholder="Code" autocomplete="off"><button id="idSubmit_SAOTCC_Continue">Verify</button>`), field: '#idTxtBx_SAOTCC_OTC' },
  aws: { html: `<form method="post" action="/done"><h1>Multi-factor authentication</h1><p>Your account is secured using multi-factor authentication (MFA).</p><label for="mfacode">MFA Code</label><input id="mfacode" name="mfacode" type="text" autocomplete="off"><button>Submit</button></form>`, field: '#mfacode' },
  'aws-bare': { html: `<form method="post" action="/done"><h1>Multi-factor authentication</h1><input id="mfacode" name="mfacode" type="text" autocomplete="off"><button>Submit</button></form>`, field: '#mfacode' },
  cloudflare: { html: `<form method="post" action="/done"><h1>Two-Factor Authentication</h1><p>Enter the 6 digit code from your authenticator app.</p><input data-testid="two-factor-login-code-input" name="twofactor_token" id="twofactor_token" type="text" inputmode="numeric" autocomplete="one-time-code"><button>Log in</button></form>`, field: '#twofactor_token' },
  react: { html: `<form method="post" action="/done" onsubmit="return false"><h1>Two-factor authentication</h1><input id="code" name="otp"><p>State: <span id="state"></span></p><button>Verify</button></form>`, script: CONTROLLED, state: '#state' },
  // No field at all (approve on the phone, or a canvas widget): the toast is the fallback.
  push: { html: '<h1>Two-factor authentication</h1><p>Approve the sign-in on your phone, or use the code from your authenticator app.</p><div id="widget"></div>', unrecognised: true },
  // Not recognisable as a code field at all: the inline menu / Alt+Shift+K must still work there.
  unknown: { html: `<form method="post" action="/done"><h1>One more step</h1><p>Type the number you see.</p><input id="c" name="answer" type="text"><button>OK</button></form>`, field: '#c', unrecognised: true },
  // The site didn't ask for 2FA this time (remembered device): straight to the signed-in page.
  skip: { signsIn: true, html: '<header><input type="search" name="q" placeholder="Search"></header><h1>Welcome back, Alice</h1><p>Your dashboard</p>' },
};

// E-mail sign-in fields (email.e2e.mjs). `exact` is Bootstrap markup with no autocomplete
// attributes, the e-mail field focused by `autofocus` before Passyble is there.
const EMAIL_EXACT = '<input type="email" class="form-control" name="username" id="inputEmail" placeholder="name@example.com" autofocus="">';
const PASSWORD_PLAIN = '<input type="password" class="form-control" name="password" id="inputPassword" placeholder="Password">';
const REMEMBER = '<div class="checkbox"><label><input type="checkbox" value="remember-me"> Remember me</label></div>';
const emailForm = (fields, button = 'Sign in', action = '/done') =>
  `<form method="post" action="${action}" class="form-signin"><h1>Please sign in</h1>${fields}${REMEMBER}
<button class="btn btn-primary" type="submit">${button}</button></form>`;

export const EMAIL_PAGES = {
  exact: emailForm(`${EMAIL_EXACT}${PASSWORD_PLAIN}`),
  // Bootstrap 4 sign-in example: screen-reader labels "Email address" / "Password".
  bootstrap: emailForm(`<label for="inputEmail" class="sr-only">Email address</label>${EMAIL_EXACT}
<label for="inputPassword" class="sr-only">Password</label>${PASSWORD_PLAIN}`),
  // Bootstrap 5 floating labels.
  floating: emailForm(`<div class="form-floating"><input type="email" class="form-control" id="floatingInput" placeholder="name@example.com" autofocus><label for="floatingInput">Email address</label></div>
<div class="form-floating"><input type="password" class="form-control" id="floatingPassword" placeholder="Password"><label for="floatingPassword">Password</label></div>`),
  noname: emailForm(`<label for="inputEmail">Email address</label><input type="email" class="form-control" id="inputEmail" placeholder="name@example.com" autofocus>${PASSWORD_PLAIN}`),
  'ac-email': emailForm(`<label for="inputEmail">Email address</label><input type="email" class="form-control" name="username" id="inputEmail" placeholder="name@example.com" autocomplete="email" autofocus>${PASSWORD_PLAIN}`),
  'ac-username': emailForm(`<label for="inputEmail">Email address</label><input type="email" class="form-control" name="username" id="inputEmail" placeholder="name@example.com" autocomplete="username" autofocus>${PASSWORD_PLAIN}`),
  // Identifier-first: the e-mail on its own, then the password on the next page.
  idfirst: emailForm(`<label for="inputEmail">Email address</label>${EMAIL_EXACT}`, 'Next', '/email/idfirst/password'),
  // The same without any sign-in wording on the page: only name="username" says what it is.
  'idfirst-plain': `<form method="post" action="/email/idfirst-plain/password"><label for="inputEmail">Email address</label>${EMAIL_EXACT}
<button class="btn btn-primary" type="submit">Continue</button></form>`,
};
const EMAIL_STEP2 = `<form method="post" action="/done"><h1>Welcome</h1><p>alice@example.com</p>
<label for="inputPassword">Password</label><input type="password" class="form-control" name="password" id="inputPassword" autofocus>
<button class="btn btn-primary" type="submit">Sign in</button></form>`;

export function startServer(agent) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const send = (status, body, headers = {}) => {
      res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', ...headers });
      res.end(body);
    };
    if (url.pathname === '/__agent') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        const reply = agent.handle(JSON.parse(body));
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(reply));
      });
      return;
    }
    if (url.pathname === '/frame/otp') {
      send(200, page('frame', otpForm('Code', '<input id="c" name="otp" inputmode="numeric" maxlength="6">')));
      return;
    }
    if (url.pathname === '/done') { send(200, page('Done', '<h1>Signed in</h1>')); return; }
    if (url.pathname === '/signup') { send(200, page('Create account', SIGNUP_FORM)); return; }
    const em = /^\/email\/([\w-]+)(\/password)?$/.exec(url.pathname);
    if (em && EMAIL_PAGES[em[1]]) {
      req.resume();
      send(200, page(`Email ${em[1]}`, em[2] ? EMAIL_STEP2 : EMAIL_PAGES[em[1]]));
      return;
    }
    const m = /^\/s\/([\w-]+)\/(login|2fa|verify|home)$/.exec(url.pathname);
    const sc = m && SCENARIOS[m[1]];
    if (!sc) { send(404, page('404', 'Not found')); return; }
    const [, id, step] = m;
    if (step === 'login' && req.method === 'POST') {
      req.resume();
      if (sc.spa) { send(200, '{}', { 'content-type': 'application/json' }); return; }
      const host = req.headers.host.replace(/^[^.]+/, sc.twofaHost || req.headers.host.split('.')[0]);
      send(303, '', { location: `http://${host}/s/${id}/${sc.signsIn ? 'home' : '2fa'}` });
      return;
    }
    if (step === 'login' || (step === 'verify' && sc.spa)) {
      send(200, page(`Sign in ${id}`, LOGIN_FORM(`/s/${id}/login`), sc.spa || ''));
      return;
    }
    send(200, page(`2FA ${id}`, sc.html, sc.script || ''));
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}
