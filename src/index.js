/* Role Finder Worker — push hub + static-asset fallback.
   Routes:
     GET  /notify     — sanity-check status page (no auth)
     POST /notify     — header x-token must match NOTIFY_TOKEN secret;
                        sends a payload-free push to every device stored in KV
     POST /subscribe  — store a browser push subscription in KV (env.SUBS)
     everything else  — served from static assets (env.ASSETS binding)
   The service worker fetches data/latest.json on push and shows the count.
   No npm dependencies — VAPID ES256 signing uses Web Crypto directly. */
import { buildVapidAuth, sha256hex } from './_util.js';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const p = url.pathname;

    if (p === '/subscribe' && request.method === 'POST') return subscribe(request, env);
    if (p === '/notify') {
      if (request.method === 'POST') return notify(request, env);
      return new Response(
        'Role Finder push hub is up. POST /notify with x-token to send pushes.',
        { headers: { 'content-type': 'text/plain' } });
    }
    return env.ASSETS.fetch(request);
  },
};

async function subscribe(request, env) {
  try {
    const sub = await request.json();
    if (!sub || typeof sub !== 'object' || !sub.endpoint ||
        !sub.keys || !sub.keys.p256dh || !sub.keys.auth) {
      return new Response('bad subscription', { status: 400 });
    }
    const id = await sha256hex(sub.endpoint);
    await env.SUBS.put(id, JSON.stringify(sub), { expirationTtl: 90 * 24 * 3600 });
    return new Response('ok');
  } catch (e) {
    return new Response('err: ' + e.message, { status: 500 });
  }
}

async function notify(request, env) {
  const token = request.headers.get('x-token') || '';
  if (!env.NOTIFY_TOKEN || token !== env.NOTIFY_TOKEN) {
    return new Response('unauthorized', { status: 401 });
  }
  let jwk;
  try {
    jwk = JSON.parse(env.VAPID_PRIVATE_KEY);
  } catch (e) {
    return new Response('no vapid key', { status: 500 });
  }

  const list = await env.SUBS.list();
  let ok = 0, dead = 0;
  for (const k of list.keys) {
    const raw = await env.SUBS.get(k.name);
    if (!raw) continue;
    let sub;
    try { sub = JSON.parse(raw); } catch (e) { continue; }
    try {
      const auth = await buildVapidAuth(sub.endpoint, jwk);
      const res = await fetch(sub.endpoint, {
        method: 'POST',
        headers: {
          Authorization: 'vapid ' + auth,
          TTL: '86400',
          'Content-Length': '0',
        },
      });
      if (res.status === 404 || res.status === 410) {
        await env.SUBS.delete(k.name); // device unsubscribed — clean up
        dead++;
      } else if (res.ok || res.status === 201) {
        ok++;
      }
    } catch (e) { /* transient — keep the subscription for next time */ }
  }
  return new Response(JSON.stringify({ ok, dead, total: list.keys.length }), {
    headers: { 'content-type': 'application/json' },
  });
}
