/* Shared helpers for Role Finder push hub (Cloudflare Pages Functions).
   VAPID ES256 JWT signing via Web Crypto (crypto.subtle) — no npm deps.
   The raw->DER conversion here is mirrored 1:1 by work/rolefinder/gen_vapid.py
   (which verifies it against the public key at generation time). */
const CH = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    s += CH[b0 >> 2];
    s += CH[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) s += CH[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) s += CH[b2 & 63];
  }
  return s;
}

function b64urlFromString(str) {
  return b64url(new TextEncoder().encode(str));
}

function derInt(x) {
  // x: Uint8Array(32) big-endian int -> DER INTEGER (drop leading zeros, pad if high bit)
  let i = 0;
  while (i < x.length - 1 && x[i] === 0) i++;
  let v = x.slice(i);
  if (v[0] & 0x80) {
    const t = new Uint8Array(v.length + 1);
    t[0] = 0; t.set(v, 1); v = t;
  }
  const out = new Uint8Array(2 + v.length);
  out[0] = 0x02; out[1] = v.length; out.set(v, 2);
  return out;
}

function rawToDer(r, s) {
  const ri = derInt(r);
  const si = derInt(s);
  const out = new Uint8Array(2 + ri.length + si.length);
  out[0] = 0x30; out[1] = ri.length + si.length;
  out.set(ri, 2); out.set(si, 2 + ri.length);
  return out;
}

export async function buildVapidAuth(endpoint, jwk) {
  const url = new URL(endpoint);
  const now = Math.floor(Date.now() / 1000);
  const header = b64urlFromString(JSON.stringify({ alg: 'ES256', typ: 'JWT' }));
  const payload = b64urlFromString(JSON.stringify({
    aud: url.origin,
    exp: now + 12 * 3600,
    sub: 'mailto:danvega@outlook.com',
  }));
  const signingInput = header + '.' + payload;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(signingInput)));
  // Web Crypto returns raw r||s (64 bytes); JWT requires DER.
  return signingInput + '.' + b64url(rawToDer(sig.slice(0, 32), sig.slice(32, 64)));
}

export async function sha256hex(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
