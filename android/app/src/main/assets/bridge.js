// Injected into index.html at build time. Routes the page's fetch('/api/...') calls
// to the Kotlin backend (WasherApi) instead of the Python server, so the UI code
// is used unchanged. Other URLs fall through to the real fetch.
(function () {
  const pending = new Map();
  let seq = 0;

  window.__nativeResolve = function (id, status, body) {
    const resolve = pending.get(id);
    if (!resolve) return;
    pending.delete(id);
    resolve(new Response(body, { status, headers: { 'Content-Type': 'application/json' } }));
  };

  const realFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = typeof input === 'string' ? input : input.url;
    if (!url.startsWith('/api/')) return realFetch(input, init);
    init = init || {};
    return new Promise(resolve => {
      const id = ++seq;
      pending.set(id, resolve);
      WasherNative.request(id, (init.method || 'GET').toUpperCase(), url, init.body == null ? '' : String(init.body));
    });
  };
})();
