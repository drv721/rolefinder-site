/* POST /notify — send a (payload-free) push to every subscribed device.
   Header: x-token must match the NOTIFY_TOKEN secret (set in Cloudflare).
   The service worker fetches /data/latest.json on push and shows the count.
   GET /notify — tiny status page for sanity checks. */
import { buildVapidAuth } from './_util.js';

export async function onRequestGet() {
  return new Response('Role Finder push hub is up. POST /notify with x-token to send pushes.', {
    headers: { 'content-type': 'text/plain' },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
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
