// Cloudflare Pages (advanced mode, _worker.js): /api/menu (GET, POST), /api/login (POST), /api/status (GET)
// Diğer her istek statik dosyalara gider (env.ASSETS).
// Gerekli: KV bağlantısı "MENU", gizli değişkenler ADMIN_USER ve ADMIN_PASS

const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const J = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });

const sha = async (s) => new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(String(s))));
const eq = (a, b) => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
};
const same = async (a, b) => eq(await sha(a), await sha(b));

async function mac(env, p) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(`${env.ADMIN_USER}\n${env.ADMIN_PASS}\n${env.ADMIN_SECRET || ""}`),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(p)));
}
async function mint(env) {
  const exp = String(Date.now() + 12 * 3600 * 1000);
  return exp + "." + (await mac(env, exp));
}
async function valid(env, t) {
  if (typeof t !== "string") return false;
  const [exp, sig] = t.split(".");
  if (!exp || !sig || !(Number(exp) > Date.now())) return false;
  return eq(enc.encode(sig), enc.encode(await mac(env, exp)));
}

const str = (v, n) => String(v ?? "").slice(0, n);
const num = (v, max) => {
  const x = Number(v);
  return Number.isFinite(x) && x >= 0 ? Math.min(x, max) : 0;
};
const slug = (v, n) => str(v, n).replace(/[^a-z0-9_-]/gi, "");

function clean(D) {
  if (!Array.isArray(D) || D.length < 1 || D.length > 40) return null;
  const out = [];
  for (const s of D) {
    if (!Array.isArray(s) || !Array.isArray(s[3]) || s[3].length > 300) return null;
    const items = s[3].map((r) =>
      Array.isArray(r)
        ? [str(r[0], 120), str(r[1], 600), num(r[2], 1e6), num(r[3], 1e5), str(r[4], 30), slug(r[5], 40), str(r[6], 120), str(r[7], 600), str(r[8], 30), r[9] ? 1 : 0]
        : null
    );
    if (items.includes(null)) return null;
    out.push([slug(s[0], 40), str(s[1], 80), str(s[2], 120), items, str(s[4], 80), str(s[5], 120)]);
  }
  const ids = out.map((s) => s[0]);
  if (ids.some((i) => !i) || new Set(ids).size !== ids.length) return null;
  return out;
}

async function api(request, env) {
  const path = new URL(request.url).pathname.replace(/\/$/, "");
  const configured = env.ADMIN_USER && env.ADMIN_PASS;

  if (path === "/api/login") {
    if (request.method !== "POST") return J({ error: "method" }, 405);
    if (!configured) return J({ error: "not_configured" }, 500);
    let b;
    try { b = await request.json(); } catch { return J({ error: "bad_json" }, 400); }
    if ((await same(b?.u ?? "", env.ADMIN_USER)) && (await same(b?.p ?? "", env.ADMIN_PASS))) {
      return J({ token: await mint(env) });
    }
    await new Promise((r) => setTimeout(r, 600));
    return J({ error: "bad_login" }, 401);
  }

  if (path === "/api/status") return J({ ok: true, kv: !!env.MENU, user: !!env.ADMIN_USER, pass: !!env.ADMIN_PASS });

  if (path !== "/api/menu") return J({ error: "not_found" }, 404);

  if (request.method === "GET") {
    if (!env.MENU) return J({ D: null });
    const d = await env.MENU.get("data", "json");
    return J(d || { D: null });
  }

  if (request.method === "POST") {
    if (!configured) return J({ error: "not_configured" }, 500);
    const auth = request.headers.get("authorization") || "";
    if (!(await valid(env, auth.replace(/^Bearer\s+/i, "")))) return J({ error: "unauthorized" }, 401);
    if (!env.MENU) return J({ error: "kv_missing" }, 500);
    const raw = await request.text();
    if (raw.length > 600000) return J({ error: "too_large" }, 413);
    let b;
    try { b = JSON.parse(raw); } catch { return J({ error: "bad_json" }, 400); }
    const D = clean(b?.D);
    if (!D) return J({ error: "invalid" }, 400);
    await env.MENU.put("data", JSON.stringify({ D, updated: Date.now() }));
    return J({ ok: true });
  }

  return J({ error: "method" }, 405);
}

export default {
  async fetch(request, env) {
    if (new URL(request.url).pathname.startsWith("/api/")) return api(request, env);
    return env.ASSETS.fetch(request);
  },
};
