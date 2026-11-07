// freshauth-callback.js — the fresh-auth popup callback (contract §5.1
// "Fresh auth", F20, G11): the one source for both listeners' landing
// pages, loaded synchronously in <head> before anything else runs
// (people.html on people.<d>, index.html on hub.<d>).
//
// The opener (freshauth.js) sends Keycloak's authorize request with this
// listener's "/" as redirect URI; Keycloak sends the popup back here with
// ?code=…&state=… (or ?error=…). The code and state are dropped from the
// URL and history at once. Only a same-origin opener (a guarded read of
// opener.location.origin: a cross-origin opener throws) gets them,
// posted to exactly this origin; the popup then closes. Without one, the
// parameters are ignored and the page loads as usual. When it handled a
// callback the page shows only "Signed in. You can close this window."
// (close() may be refused). Both listeners answer with
// Referrer-Policy: no-referrer, and the pages carry the same meta tag.
window.portcullisFreshAuthCallback = (function () {
  'use strict';
  var q = new URLSearchParams(location.search);
  if (!q.has('code') && !q.has('state') && !q.has('error')) return false;
  var msg = { type: 'portcullis-fresh-auth', code: q.get('code') || '', state: q.get('state') || '', error: q.get('error') || '' };
  history.replaceState(null, '', location.pathname + location.hash);
  var op = null;
  try {
    if (window.opener && window.opener !== window && window.opener.location.origin === location.origin) op = window.opener;
  } catch (e) {
    op = null;
  }
  if (!op) return false;
  op.postMessage(msg, location.origin);
  window.close();
  document.documentElement.style.visibility = 'hidden';
  document.addEventListener('DOMContentLoaded', function () {
    document.body.textContent = 'Signed in. You can close this window.';
    document.documentElement.style.visibility = '';
  });
  return true;
})();
