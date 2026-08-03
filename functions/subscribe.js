/* POST /subscribe — store a browser push subscription in KV. */
import { sha256hex } from './_util.js';

export async function onRequestPost(context) {
  const { request, env } = context;
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
