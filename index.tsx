import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { SQL } from "bun";
// fresh connection pool per loaded version, so cached statements never outlive a schema change
const sql = new SQL(Bun.env.DATABASE_URL as string);

// ================= config =================
const ADMIN_PASSWORD = Bun.env.ADMIN_PASSWORD || "";
const TG_TOKEN = Bun.env.TELEGRAM_BOT_TOKEN || "";
const TG_CHAT = Bun.env.TELEGRAM_CHAT_ID || "";
const PUBLIC_URL = Bun.env.PUBLIC_URL || (Bun.env.RAILWAY_PUBLIC_DOMAIN ? "https://" + Bun.env.RAILWAY_PUBLIC_DOMAIN : "");
const SEED_TOKEN = Bun.env.SEED_TOKEN || "";

// ================= schema =================
await sql`CREATE TABLE IF NOT EXISTS settings (k text PRIMARY KEY, v text NOT NULL)`;
await sql`CREATE TABLE IF NOT EXISTS clients (
  id uuid PRIMARY KEY, name text NOT NULL, slug text, token text UNIQUE NOT NULL,
  pin_hash text, report jsonb, interview jsonb, archived boolean DEFAULT false,
  created_at timestamptz DEFAULT now(), updated_at timestamptz DEFAULT now(), last_client_at timestamptz)`;
await sql`CREATE TABLE IF NOT EXISTS periods (
  id uuid PRIMARY KEY, client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name text NOT NULL, quota int NOT NULL DEFAULT 20, status text NOT NULL DEFAULT 'open',
  sort int NOT NULL DEFAULT 0, submitted_at timestamptz, created_at timestamptz DEFAULT now())`;
await sql`CREATE TABLE IF NOT EXISTS categories (
  id uuid PRIMARY KEY, client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name text NOT NULL, note text DEFAULT '', sort int NOT NULL DEFAULT 0)`;
await sql`CREATE TABLE IF NOT EXISTS keywords (
  id uuid PRIMARY KEY, client_id uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  category_id uuid REFERENCES categories(id) ON DELETE SET NULL,
  kw text NOT NULL, vol int, hi double precision, comp text DEFAULT '', intent text DEFAULT '',
  content text DEFAULT '', note text DEFAULT '', rec boolean DEFAULT false, hidden boolean DEFAULT false,
  sort int NOT NULL DEFAULT 0, created_at timestamptz DEFAULT now())`;
await sql`CREATE TABLE IF NOT EXISTS selections (
  period_id uuid NOT NULL REFERENCES periods(id) ON DELETE CASCADE,
  keyword_id uuid NOT NULL REFERENCES keywords(id) ON DELETE CASCADE,
  by_whom text DEFAULT 'client', created_at timestamptz DEFAULT now(),
  PRIMARY KEY (period_id, keyword_id))`;
await sql`CREATE INDEX IF NOT EXISTS kw_client ON keywords(client_id)`;
await sql`ALTER TABLE keywords ADD COLUMN IF NOT EXISTS path text DEFAULT ''`;
await sql`ALTER TABLE clients ADD COLUMN IF NOT EXISTS contract_total int`;
await sql`ALTER TABLE clients ADD COLUMN IF NOT EXISTS notion_page_id text`;
await sql`ALTER TABLE clients ADD COLUMN IF NOT EXISTS notion_synced_at timestamptz`;

let SECRET = Bun.env.SESSION_SECRET || "";
if (!SECRET) {
  const r = await sql`SELECT v FROM settings WHERE k='secret'`;
  if (r.length) SECRET = r[0].v;
  else { SECRET = randToken(48); await sql`INSERT INTO settings (k,v) VALUES ('secret', ${SECRET})`; }
}

// ================= helpers =================
function randToken(n = 32) {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const b = crypto.getRandomValues(new Uint8Array(n));
  return Array.from(b, x => a[x % a.length]).join("");
}
async function hmac(data: string) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return Buffer.from(sig).toString("base64url");
}
function safeEq(a: string, b: string) {
  if (a.length !== b.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const normKw = (s: string) => String(s || "").trim().replace(/\s+/g, " ")
  .replace(/([\u3100-\u312f\u4e00-\u9fff])\s+(?=\S)/g, "$1").replace(/(\S)\s+(?=[\u3100-\u312f\u4e00-\u9fff])/g, "$1");
const kwKey = (s: string) => normKw(s).toLowerCase().replace(/\s/g, "");
const num = (v: any) => (v === null || v === undefined || v === "" || isNaN(Number(v))) ? null : Number(v);

async function notify(text: string) {
  if (!TG_TOKEN || !TG_CHAT) return;
  try {
    await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: TG_CHAT, text, disable_web_page_preview: true }),
    });
  } catch (e) { console.error("telegram", e); }
}

const COOKIE_OPTS = { httpOnly: true, secure: true, sameSite: "Lax" as const, path: "/" };
async function adminOk(c: any) {
  const v = getCookie(c, "adm");
  if (!v || !ADMIN_PASSWORD) return false;
  const [exp, sig] = v.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, await hmac("adm." + exp + "." + ADMIN_PASSWORD.length));
}
async function clientCookieOk(c: any, cl: any) {
  const v = getCookie(c, "c_" + cl.id.slice(0, 8));
  if (!v) return false;
  const [exp, sig] = v.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEq(sig, await hmac("c." + cl.id + "." + exp + "." + (cl.pin_hash || "").slice(-12)));
}
const pinFails = new Map<string, { n: number; until: number }>();

// ================= data access =================
async function loadClientFull(id: string) {
  const [cl] = await sql`SELECT * FROM clients WHERE id=${id}`;
  if (!cl) return null;
  const periods = await sql`SELECT * FROM periods WHERE client_id=${id} ORDER BY sort, created_at`;
  const cats = await sql`SELECT * FROM categories WHERE client_id=${id} ORDER BY sort, name`;
  const kws = await sql`SELECT * FROM keywords WHERE client_id=${id} ORDER BY sort, vol DESC NULLS LAST, kw`;
  const sels = await sql`SELECT s.period_id, s.keyword_id, s.by_whom FROM selections s JOIN periods p ON p.id=s.period_id WHERE p.client_id=${id}`;
  return { client: cl, periods, cats, kws, sels };
}
async function periodLimit(client: any, periods: any[], cur: any) {
  if (client.contract_total == null) return { limit: cur.quota, past: 0, remainTotal: null };
  const [r] = await sql`SELECT count(*)::int AS n FROM selections s JOIN periods p ON p.id=s.period_id WHERE p.client_id=${client.id} AND p.id<>${cur.id}`;
  const remainTotal = Math.max(0, client.contract_total - r.n);
  return { limit: cur.quota ? Math.min(remainTotal, cur.quota) : remainTotal, past: r.n, remainTotal };
}
function currentPeriod(periods: any[]) { return periods.length ? periods[periods.length - 1] : null; }
async function clientStats(id: string) {
  const periods = await sql`SELECT * FROM periods WHERE client_id=${id} ORDER BY sort, created_at`;
  const cur = currentPeriod(periods);
  let selected = 0;
  if (cur) { const [r] = await sql`SELECT count(*)::int AS n FROM selections WHERE period_id=${cur.id}`; selected = r.n; }
  const [k] = await sql`SELECT count(*)::int AS n FROM keywords WHERE client_id=${id} AND hidden=false`;
  const [cl] = await sql`SELECT * FROM clients WHERE id=${id}`;
  const lim = cur ? await periodLimit(cl, periods, cur) : { limit: 0, past: 0 };
  return { period: cur, selected, keywords: k.n, periods: periods.length, limit: lim.limit, past: lim.past, contract: cl.contract_total ?? null };
}

// ================= app =================
const app = new Hono();
app.use("*", async (c, next) => { await next(); c.header("X-Frame-Options", "DENY"); c.header("Referrer-Policy", "no-referrer"); c.header("X-Robots-Tag", "noindex, nofollow"); });
app.get("/", c => c.redirect("/admin"));
app.get("/robots.txt", c => c.text("User-agent: *\nDisallow: /\n"));
app.get("/health", c => c.text("ok"));

// ---------- admin auth ----------
app.post("/api/admin/login", async c => {
  if (!ADMIN_PASSWORD) return c.json({ error: "尚未設定管理密碼：請在 Railway 的 Variables 新增 ADMIN_PASSWORD" }, 400);
  const { password } = await c.req.json().catch(() => ({}));
  const ip = c.req.header("x-forwarded-for") || "x";
  const f = pinFails.get("adm" + ip);
  if (f && f.until > Date.now()) return c.json({ error: "嘗試次數過多，請稍後再試" }, 429);
  if (typeof password !== "string" || !safeEq(password, ADMIN_PASSWORD)) {
    const n = (f?.n || 0) + 1; pinFails.set("adm" + ip, { n, until: n >= 8 ? Date.now() + 15 * 60e3 : 0 });
    return c.json({ error: "密碼錯誤" }, 401);
  }
  pinFails.delete("adm" + ip);
  const exp = String(Date.now() + 14 * 864e5);
  setCookie(c, "adm", exp + "." + await hmac("adm." + exp + "." + ADMIN_PASSWORD.length), { ...COOKIE_OPTS, maxAge: 14 * 86400 });
  return c.json({ ok: true });
});
app.post("/api/admin/logout", c => { deleteCookie(c, "adm", { path: "/" }); return c.json({ ok: true }); });
app.use("/api/admin/*", async (c, next) => {
  if (c.req.path === "/api/admin/login" || c.req.path === "/api/admin/logout") return next();
  if (!(await adminOk(c))) return c.json({ error: "unauthorized" }, 401);
  return next();
});
app.get("/api/admin/me", c => c.json({ ok: true, telegram: !!(TG_TOKEN && TG_CHAT), notion: !!(Bun.env.NOTION_TOKEN && Bun.env.NOTION_DB_ID), publicUrl: PUBLIC_URL }));

app.get("/api/admin/clients", async c => {
  const cls = await sql`SELECT id,name,token,archived,updated_at,last_client_at FROM clients ORDER BY archived, name`;
  const out = [];
  for (const cl of cls) out.push({ ...cl, stats: await clientStats(cl.id) });
  return c.json(out);
});
app.post("/api/admin/clients", async c => {
  const b = await c.req.json();
  const name = String(b.name || "").trim(); const pin = String(b.pin || "").trim();
  if (!name) return c.json({ error: "請輸入客戶名稱" }, 400);
  if (!/^\d{4,6}$/.test(pin)) return c.json({ error: "PIN 碼需為 4–6 位數字" }, 400);
  const id = crypto.randomUUID();
  await sql`INSERT INTO clients (id,name,token,pin_hash,report,interview) VALUES (${id},${name},${randToken(32)},${await Bun.password.hash(pin)},${(b.report || null) as any}::jsonb,${(b.interview || defaultInterview(name)) as any}::jsonb)`;
  await sql`INSERT INTO periods (id,client_id,name,quota,sort) VALUES (${crypto.randomUUID()},${id},'第一期',${Number(b.quota) || 20},1)`;
  return c.json({ id });
});
app.get("/api/admin/clients/:id", async c => {
  const d = await loadClientFull(c.req.param("id"));
  if (!d) return c.json({ error: "not found" }, 404);
  const { pin_hash, ...client } = d.client;
  return c.json({ ...d, client: { ...client, hasPin: !!pin_hash } });
});
app.patch("/api/admin/clients/:id", async c => {
  const id = c.req.param("id"); const b = await c.req.json();
  if (b.name !== undefined) await sql`UPDATE clients SET name=${String(b.name)}, updated_at=now() WHERE id=${id}`;
  if (b.pin !== undefined) {
    if (!/^\d{4,6}$/.test(String(b.pin))) return c.json({ error: "PIN 碼需為 4–6 位數字" }, 400);
    await sql`UPDATE clients SET pin_hash=${await Bun.password.hash(String(b.pin))}, updated_at=now() WHERE id=${id}`;
  }
  if (b.report !== undefined) await sql`UPDATE clients SET report=${(b.report) as any}::jsonb, updated_at=now() WHERE id=${id}`;
  if (b.interview !== undefined) await sql`UPDATE clients SET interview=${(b.interview) as any}::jsonb, updated_at=now() WHERE id=${id}`;
  if (b.archived !== undefined) await sql`UPDATE clients SET archived=${!!b.archived}, updated_at=now() WHERE id=${id}`;
  if (b.contract_total !== undefined) await sql`UPDATE clients SET contract_total=${b.contract_total === null || b.contract_total === "" ? null : Math.max(0, Number(b.contract_total) || 0)}, updated_at=now() WHERE id=${id}`;
  if (b.resetToken) await sql`UPDATE clients SET token=${randToken(32)}, updated_at=now() WHERE id=${id}`;
  return c.json({ ok: true });
});
// periods
app.post("/api/admin/clients/:id/periods", async c => {
  const id = c.req.param("id"); const b = await c.req.json();
  const [m] = await sql`SELECT coalesce(max(sort),0)::int AS m FROM periods WHERE client_id=${id}`;
  const pid = crypto.randomUUID();
  await sql`INSERT INTO periods (id,client_id,name,quota,sort) VALUES (${pid},${id},${String(b.name || "新一期")},${Number(b.quota) || 20},${m.m + 1})`;
  await sql`UPDATE clients SET updated_at=now() WHERE id=${id}`;
  return c.json({ id: pid });
});
app.patch("/api/admin/periods/:pid", async c => {
  const pid = c.req.param("pid"); const b = await c.req.json();
  if (b.name !== undefined) await sql`UPDATE periods SET name=${String(b.name)} WHERE id=${pid}`;
  if (b.quota !== undefined) await sql`UPDATE periods SET quota=${Math.max(0, Number(b.quota) || 0)} WHERE id=${pid}`;
  if (b.status === "open") await sql`UPDATE periods SET status='open', submitted_at=NULL WHERE id=${pid}`;
  if (b.status === "submitted") await sql`UPDATE periods SET status='submitted', submitted_at=now() WHERE id=${pid}`;
  return c.json({ ok: true });
});
app.delete("/api/admin/periods/:pid", async c => {
  const pid = c.req.param("pid");
  const [n] = await sql`SELECT count(*)::int AS n FROM selections WHERE period_id=${pid}`;
  if (n.n > 0) return c.json({ error: "這一期已有選字，無法刪除" }, 400);
  await sql`DELETE FROM periods WHERE id=${pid}`;
  return c.json({ ok: true });
});
app.post("/api/admin/periods/:pid/toggle", async c => {
  const pid = c.req.param("pid"); const { keyword_id, selected } = await c.req.json();
  if (selected) await sql`INSERT INTO selections (period_id,keyword_id,by_whom) VALUES (${pid},${keyword_id},'admin') ON CONFLICT DO NOTHING`;
  else await sql`DELETE FROM selections WHERE period_id=${pid} AND keyword_id=${keyword_id}`;
  return c.json({ ok: true });
});
// categories
app.post("/api/admin/clients/:id/categories", async c => {
  const id = c.req.param("id"); const b = await c.req.json();
  const [m] = await sql`SELECT coalesce(max(sort),0)::int AS m FROM categories WHERE client_id=${id}`;
  const cid = crypto.randomUUID();
  await sql`INSERT INTO categories (id,client_id,name,note,sort) VALUES (${cid},${id},${String(b.name || "新分類")},${String(b.note || "")},${m.m + 1})`;
  return c.json({ id: cid });
});
app.patch("/api/admin/categories/:cid", async c => {
  const cid = c.req.param("cid"); const b = await c.req.json();
  if (b.name !== undefined) await sql`UPDATE categories SET name=${String(b.name)} WHERE id=${cid}`;
  if (b.note !== undefined) await sql`UPDATE categories SET note=${String(b.note)} WHERE id=${cid}`;
  if (b.sort !== undefined) await sql`UPDATE categories SET sort=${Number(b.sort)} WHERE id=${cid}`;
  return c.json({ ok: true });
});
app.delete("/api/admin/categories/:cid", async c => {
  await sql`DELETE FROM categories WHERE id=${c.req.param("cid")}`; // keywords fall back to 未分類
  return c.json({ ok: true });
});
// keywords
app.post("/api/admin/clients/:id/keywords", async c => {
  const id = c.req.param("id"); const b = await c.req.json();
  const rows: any[] = Array.isArray(b.rows) ? b.rows : [];
  const existing = await sql`SELECT id, kw FROM keywords WHERE client_id=${id}`;
  const map = new Map(existing.map((r: any) => [kwKey(r.kw), r.id]));
  let added = 0, updated = 0;
  await sql.begin(async tx => {
    for (const r of rows) {
      const kw = normKw(r.kw); if (!kw) continue;
      const k = kwKey(kw);
      const ex = map.get(k);
      if (ex) {
        if (b.mode === "skip") continue;
        await tx`UPDATE keywords SET vol=coalesce(${num(r.vol)},vol), hi=coalesce(${num(r.hi)},hi), comp=coalesce(nullif(${r.comp || ""},''),comp) WHERE id=${ex}`;
        updated++;
      } else {
        const nid = crypto.randomUUID();
        await tx`INSERT INTO keywords (id,client_id,category_id,kw,vol,hi,comp,intent,content,note,rec)
          VALUES (${nid},${id},${r.category_id || b.category_id || null},${kw},${num(r.vol)},${num(r.hi)},${r.comp || ""},${r.intent || ""},${r.content || ""},${r.note || ""},${!!r.rec})`;
        map.set(k, nid); added++;
      }
    }
  });
  await sql`UPDATE clients SET updated_at=now() WHERE id=${id}`;
  return c.json({ added, updated });
});
app.patch("/api/admin/keywords/:kid", async c => {
  const kid = c.req.param("kid"); const b = await c.req.json();
  const f = (k: string) => b[k] !== undefined;
  if (f("kw")) await sql`UPDATE keywords SET kw=${normKw(b.kw)} WHERE id=${kid}`;
  if (f("vol")) await sql`UPDATE keywords SET vol=${num(b.vol)} WHERE id=${kid}`;
  if (f("hi")) await sql`UPDATE keywords SET hi=${num(b.hi)} WHERE id=${kid}`;
  if (f("comp")) await sql`UPDATE keywords SET comp=${String(b.comp ?? "")} WHERE id=${kid}`;
  if (f("intent")) await sql`UPDATE keywords SET intent=${String(b.intent ?? "")} WHERE id=${kid}`;
  if (f("content")) await sql`UPDATE keywords SET content=${String(b.content ?? "")} WHERE id=${kid}`;
  if (f("note")) await sql`UPDATE keywords SET note=${String(b.note ?? "")} WHERE id=${kid}`;
  if (f("path")) await sql`UPDATE keywords SET path=${String(b.path ?? "")} WHERE id=${kid}`;
  if (f("category_id")) await sql`UPDATE keywords SET category_id=${b.category_id || null} WHERE id=${kid}`;
  if (f("rec")) await sql`UPDATE keywords SET rec=${!!b.rec} WHERE id=${kid}`;
  if (f("hidden")) await sql`UPDATE keywords SET hidden=${!!b.hidden} WHERE id=${kid}`;
  return c.json({ ok: true });
});
app.post("/api/admin/keywords/bulk", async c => {
  const b = await c.req.json(); const ids: string[] = b.ids || [];
  if (!ids.length) return c.json({ ok: true });
  if (b.action === "move") await sql`UPDATE keywords SET category_id=${b.category_id || null} WHERE id IN ${sql(ids)}`;
  if (b.action === "hide") await sql`UPDATE keywords SET hidden=true WHERE id IN ${sql(ids)}`;
  if (b.action === "show") await sql`UPDATE keywords SET hidden=false WHERE id IN ${sql(ids)}`;
  if (b.action === "delete") {
    const used = await sql`SELECT DISTINCT keyword_id FROM selections WHERE keyword_id IN ${sql(ids)}`;
    const usedSet = new Set(used.map((r: any) => r.keyword_id));
    const del = ids.filter(i => !usedSet.has(i)); const hide = ids.filter(i => usedSet.has(i));
    if (del.length) await sql`DELETE FROM keywords WHERE id IN ${sql(del)}`;
    if (hide.length) await sql`UPDATE keywords SET hidden=true WHERE id IN ${sql(hide)}`;
    return c.json({ deleted: del.length, hidden: hide.length });
  }
  return c.json({ ok: true });
});

// ---------- seed (one-time) ----------
app.post("/api/seed", async c => {
  if (!SEED_TOKEN || !safeEq(c.req.header("x-seed-token") || "", SEED_TOKEN)) return c.json({ error: "forbidden" }, 403);
  const [n] = await sql`SELECT count(*)::int AS n FROM clients`;
  if (n.n > 0) return c.json({ error: "already seeded" }, 409);
  const list = await c.req.json(); const out: any[] = [];
  for (const s of list) {
    const id = crypto.randomUUID(); const token = randToken(32); const pin = String(Math.floor(100000 + Math.random() * 900000));
    await sql`INSERT INTO clients (id,name,slug,token,pin_hash,report,interview) VALUES (${id},${s.name},${s.slug},${token},${await Bun.password.hash(pin)},${(s.report) as any}::jsonb,${(s.interview) as any}::jsonb)`;
    const pids: string[] = [];
    let ps = 0;
    for (const p of s.periods) { const pid = crypto.randomUUID(); pids.push(pid); ps++;
      await sql`INSERT INTO periods (id,client_id,name,quota,status,sort,submitted_at) VALUES (${pid},${id},${p.name},${p.quota},${p.status},${ps},${p.status === "submitted" ? new Date() : null})`; }
    const importedPid = s.periods.findIndex((p: any) => p.imported);
    let cs = 0;
    for (const cat of s.cats) {
      const cid = crypto.randomUUID(); cs++;
      await sql`INSERT INTO categories (id,client_id,name,note,sort) VALUES (${cid},${id},${cat.name},${cat.note || ""},${cs})`;
      let ks = 0;
      await sql.begin(async tx => {
        for (const k of cat.kws) {
          const kid = crypto.randomUUID(); ks++;
          await tx`INSERT INTO keywords (id,client_id,category_id,kw,vol,hi,comp,intent,content,note,rec,sort) VALUES (${kid},${id},${cid},${k.kw},${num(k.vol)},${num(k.hi)},${k.comp || ""},${k.intent || ""},${k.content || ""},${k.note || ""},${!!k.rec},${ks})`;
          if (k.sel && importedPid >= 0) await tx`INSERT INTO selections (period_id,keyword_id,by_whom) VALUES (${pids[importedPid]},${kid},'import')`;
        }
      });
    }
    out.push({ name: s.name, id, token, pin });
  }
  return c.json(out);
});


// ---------- ops: curate a client's candidate list (DEPLOY_TOKEN) ----------
app.post("/api/ops/curate", async c => {
  const T = Bun.env.DEPLOY_TOKEN || "";
  if (!T || !safeEq(c.req.header("x-deploy-token") || "", T)) return c.json({ error: "forbidden" }, 403);
  const b = await c.req.json(); const id = b.client_id;
  const [cl] = await sql`SELECT id FROM clients WHERE id=${id}`; if (!cl) return c.json({ error: "no client" }, 404);
  const periods = await sql`SELECT * FROM periods WHERE client_id=${id} ORDER BY sort, created_at`;
  const cur = currentPeriod(periods);
  const kws = await sql`SELECT id, kw FROM keywords WHERE client_id=${id}`;
  const map = new Map(kws.map((r: any) => [kwKey(r.kw), r.id]));
  const keep = new Set<string>(); const report: any = { updated: 0, added: 0, hidden: 0, past: 0 };
  await sql.begin(async tx => {
    await tx`UPDATE categories SET sort = sort + 100 WHERE client_id=${id}`;
    let cs = 0;
    for (const cat of b.categories || []) {
      cs++; const cid = crypto.randomUUID();
      await tx`INSERT INTO categories (id,client_id,name,note,sort) VALUES (${cid},${id},${cat.name},${cat.note || ""},${cs})`;
      let ks = 0;
      for (const it of cat.items || []) {
        ks++; const k = kwKey(it.kw); let kid = map.get(k);
        if (kid) {
          await tx`UPDATE keywords SET category_id=${cid}, hidden=false, sort=${ks}, intent=${it.intent || ""}, content=${it.content || ""}, path=${it.path || ""}, note=${it.note || ""}, rec=${!!it.rec}, vol=coalesce(${num(it.vol)},vol), hi=coalesce(${num(it.hi)},hi) WHERE id=${kid}`;
          report.updated++;
        } else {
          kid = crypto.randomUUID();
          await tx`INSERT INTO keywords (id,client_id,category_id,kw,vol,hi,intent,content,path,note,rec,sort) VALUES (${kid},${id},${cid},${normKw(it.kw)},${num(it.vol)},${num(it.hi)},${it.intent || ""},${it.content || ""},${it.path || ""},${it.note || ""},${!!it.rec},${ks})`;
          map.set(k, kid); report.added++;
        }
        keep.add(kid);
      }
    }
    if (b.pastCategory && cur) {
      const past = await tx`SELECT DISTINCT s.keyword_id FROM selections s JOIN periods p ON p.id=s.period_id WHERE p.client_id=${id} AND p.id<>${cur.id}`;
      if (past.length) {
        const pid = crypto.randomUUID();
        await tx`INSERT INTO categories (id,client_id,name,note,sort) VALUES (${pid},${id},${b.pastCategory.name},${b.pastCategory.note || ""},${cs + 1})`;
        for (const r of past) { if (keep.has(r.keyword_id)) continue; await tx`UPDATE keywords SET category_id=${pid}, hidden=false WHERE id=${r.keyword_id}`; keep.add(r.keyword_id); report.past++; }
      }
    }
    if (b.hideOthers) {
      const all = await tx`SELECT id FROM keywords WHERE client_id=${id} AND hidden=false`;
      for (const r of all) if (!keep.has(r.id)) { await tx`UPDATE keywords SET hidden=true WHERE id=${r.id}`; report.hidden++; }
    }
    if (b.quota && cur) await tx`UPDATE periods SET quota=${Number(b.quota)} WHERE id=${cur.id}`;
    if (b.periodName && cur) await tx`UPDATE periods SET name=${String(b.periodName)} WHERE id=${cur.id}`;
  });
  return c.json(report);
});


app.post("/api/ops/past-select", async c => {
  const T = Bun.env.DEPLOY_TOKEN || "";
  if (!T || !safeEq(c.req.header("x-deploy-token") || "", T)) return c.json({ error: "forbidden" }, 403);
  const b = await c.req.json();
  const [p] = await sql`SELECT * FROM periods WHERE client_id=${b.client_id} AND name=${b.period_name}`;
  if (!p) return c.json({ error: "no period" }, 404);
  const [cat] = b.category_name ? await sql`SELECT id FROM categories WHERE client_id=${b.client_id} AND name=${b.category_name}` : [null];
  const kws = await sql`SELECT id, kw FROM keywords WHERE client_id=${b.client_id}`;
  let kid = kws.find((r: any) => kwKey(r.kw) === kwKey(b.kw))?.id;
  if (!kid) { kid = crypto.randomUUID(); await sql`INSERT INTO keywords (id,client_id,category_id,kw,vol,hi) VALUES (${kid},${b.client_id},${cat?.id || null},${normKw(b.kw)},${num(b.vol)},${num(b.hi)})`; }
  else await sql`UPDATE keywords SET hidden=false, category_id=coalesce(${cat?.id || null},category_id) WHERE id=${kid}`;
  await sql`INSERT INTO selections (period_id,keyword_id,by_whom) VALUES (${p.id},${kid},'admin') ON CONFLICT DO NOTHING`;
  const [n] = await sql`SELECT count(*)::int AS n FROM selections WHERE period_id=${p.id}`;
  if (n.n > p.quota) await sql`UPDATE periods SET quota=${n.n} WHERE id=${p.id}`;
  return c.json({ ok: true, count: n.n });
});


app.post("/api/ops/client", async c => {
  const T = Bun.env.DEPLOY_TOKEN || "";
  if (!T || !safeEq(c.req.header("x-deploy-token") || "", T)) return c.json({ error: "forbidden" }, 403);
  const b = await c.req.json();
  if (b.contract_total !== undefined) await sql`UPDATE clients SET contract_total=${b.contract_total} WHERE id=${b.client_id}`;
  return c.json({ ok: true });
});


// ---------- Notion ----------
async function notion(path: string, body?: any) {
  const r = await fetch("https://api.notion.com/v1" + path, { method: body ? "POST" : "GET",
    headers: { Authorization: "Bearer " + (Bun.env.NOTION_TOKEN || ""), "Notion-Version": "2022-06-28", "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined });
  const j = await r.json(); if (!r.ok) throw new Error(j.message || ("notion " + r.status)); return j;
}
function propText(p: any): any {
  if (!p) return null;
  switch (p.type) {
    case "title": return p.title.map((t: any) => t.plain_text).join("");
    case "rich_text": return p.rich_text.map((t: any) => t.plain_text).join("");
    case "select": return p.select?.name ?? null;
    case "multi_select": return p.multi_select.map((x: any) => x.name);
    case "status": return p.status?.name ?? null;
    case "number": return p.number;
    case "checkbox": return p.checkbox;
    case "date": return p.date?.start ?? null;
    case "url": return p.url;
    case "relation": return p.relation.map((x: any) => x.id);
    case "formula": return p.formula?.[p.formula.type] ?? null;
    case "rollup": return p.rollup?.array ? p.rollup.array.map(propText) : (p.rollup?.[p.rollup.type] ?? null);
    case "people": return p.people.map((x: any) => x.name || x.id);
    case "created_time": return p.created_time; case "last_edited_time": return p.last_edited_time;
    default: return p[p.type] ?? null;
  }
}
async function notionAll(dbId: string) {
  const rows: any[] = []; let cursor: any = undefined;
  do { const j = await notion(`/databases/${dbId}/query`, { page_size: 100, start_cursor: cursor });
    for (const pg of j.results) { const o: any = { _id: pg.id }; for (const [k, v] of Object.entries(pg.properties)) o[k] = propText(v); rows.push(o); }
    cursor = j.has_more ? j.next_cursor : undefined; } while (cursor);
  return rows;
}

async function notionSync(clientId: string) {
  const dbId = Bun.env.NOTION_DB_ID || ""; if (!dbId || !Bun.env.NOTION_TOKEN) throw new Error("尚未設定 NOTION_TOKEN 或 NOTION_DB_ID");
  const [cl] = await sql`SELECT * FROM clients WHERE id=${clientId}`; if (!cl) throw new Error("找不到客戶");
  let page: any = null;
  if (cl.notion_page_id) { try { const pg = await notion(`/pages/${cl.notion_page_id}`); page = { _id: pg.id }; for (const [k, v] of Object.entries(pg.properties)) page[k] = propText(v); } catch { page = null; } }
  if (!page) {
    const rows = await notionAll(dbId);
    const nm = (x: string) => String(x || "").replace(/\s/g, "");
    page = rows.find(r => nm(r["專案名稱"]) === nm(cl.name)) || rows.find(r => nm(r["專案名稱"]).includes(nm(cl.name)) || nm(cl.name).includes(nm(r["專案名稱"]) || "∅"));
    if (!page) throw new Error("Notion 專案資料庫找不到名稱相符的專案：" + cl.name);
    await sql`UPDATE clients SET notion_page_id=${page._id} WHERE id=${clientId}`;
  }
  const kwList = String(page["關鍵字"] || "").split(/[,，、\n]/).map((x: string) => normKw(x)).filter(Boolean);
  const total = num(page["文章數量（自動計數，內有公式勿動）"]);
  const periods = await sql`SELECT * FROM periods WHERE client_id=${clientId} ORDER BY sort, created_at`;
  const cur = currentPeriod(periods);
  let target = [...periods].reverse().find((p: any) => cur && p.id !== cur.id && p.status !== "open");
  if (!target) {
    const pid = crypto.randomUUID();
    await sql`UPDATE periods SET sort = sort + 1 WHERE client_id=${clientId}`;
    await sql`INSERT INTO periods (id,client_id,name,quota,status,sort,submitted_at) VALUES (${pid},${clientId},'既有選字（Notion）',0,'submitted',0,now())`;
    target = { id: pid };
  }
  const kws = await sql`SELECT id, kw, category_id FROM keywords WHERE client_id=${clientId}`;
  const map = new Map(kws.map((r: any) => [kwKey(r.kw), r]));
  const sels = await sql`SELECT s.keyword_id, s.period_id FROM selections s JOIN periods p ON p.id=s.period_id WHERE p.client_id=${clientId}`;
  const selected = new Set(sels.filter((s: any) => !cur || s.period_id !== cur.id).map((s: any) => s.keyword_id));
  const [pastCat] = await sql`SELECT id FROM categories WHERE client_id=${clientId} AND name LIKE '%已選%' ORDER BY sort LIMIT 1`;
  const out: any = { project: page["專案名稱"], notionKeywords: kwList, contract_total: total, added: [], marked: [], onlyInSystem: [] };
  for (const k of kwList) {
    let r: any = map.get(kwKey(k));
    if (!r) { const id = crypto.randomUUID(); await sql`INSERT INTO keywords (id,client_id,category_id,kw) VALUES (${id},${clientId},${pastCat?.id || null},${k})`; r = { id }; map.set(kwKey(k), r); out.added.push(k); }
    else await sql`UPDATE keywords SET hidden=false WHERE id=${r.id}`;
    if (!selected.has(r.id)) {
      if (cur) await sql`DELETE FROM selections WHERE period_id=${cur.id} AND keyword_id=${r.id}`;
      await sql`INSERT INTO selections (period_id,keyword_id,by_whom) VALUES (${target.id},${r.id},'notion') ON CONFLICT DO NOTHING`;
      selected.add(r.id); out.marked.push(k);
    }
  }
  const nk = new Set(kwList.map(kwKey));
  for (const s of sels) if (!cur || s.period_id !== cur.id) { const r: any = kws.find((x: any) => x.id === s.keyword_id); if (r && !nk.has(kwKey(r.kw))) out.onlyInSystem.push(r.kw); }
  out.onlyInSystem = [...new Set(out.onlyInSystem)];
  if (total != null) await sql`UPDATE clients SET contract_total=${total} WHERE id=${clientId}`;
  await sql`UPDATE clients SET notion_synced_at=now() WHERE id=${clientId}`;
  return out;
}
app.post("/api/ops/notion-sync", async c => {
  const T = Bun.env.DEPLOY_TOKEN || "";
  if (!T || !safeEq(c.req.header("x-deploy-token") || "", T)) return c.json({ error: "forbidden" }, 403);
  const b = await c.req.json();
  try { return c.json(await notionSync(b.client_id)); } catch (e: any) { return c.json({ error: e.message }, 400); }
});

app.post("/api/ops/notion-peek", async c => {
  const T = Bun.env.DEPLOY_TOKEN || "";
  if (!T || !safeEq(c.req.header("x-deploy-token") || "", T)) return c.json({ error: "forbidden" }, 403);
  const b = await c.req.json().catch(() => ({}));
  const dbId = b.db || Bun.env.NOTION_DB_ID || "";
  try {
    const db = await notion(`/databases/${dbId}`);
    const schema = Object.fromEntries(Object.entries(db.properties).map(([k, v]: any) => [k, { type: v.type, options: v.select?.options?.map((o: any) => o.name) || v.multi_select?.options?.map((o: any) => o.name) || v.status?.options?.map((o: any) => o.name) }]));
    const rows = await notionAll(dbId);
    return c.json({ title: db.title?.map((t: any) => t.plain_text).join(""), schema, count: rows.length, rows: b.all ? rows : rows.slice(0, 40) });
  } catch (e: any) { return c.json({ error: e.message }, 500); }
});


app.post("/api/admin/clients/:id/notion-sync", async c => {
  try { return c.json(await notionSync(c.req.param("id"))); } catch (e: any) { return c.json({ error: e.message }, 400); }
});
app.post("/api/admin/notion-sync-all", async c => {
  const cls = await sql`SELECT id, name FROM clients WHERE archived=false`; const out: any[] = [];
  for (const cl of cls) { try { const r = await notionSync(cl.id); out.push({ name: cl.name, ok: true, marked: r.marked.length, added: r.added.length, onlyInSystem: r.onlyInSystem, total: r.contract_total }); } catch (e: any) { out.push({ name: cl.name, ok: false, error: e.message }); } }
  return c.json(out);
});
app.post("/api/admin/telegram-test", async c => {
  if (!TG_TOKEN || !TG_CHAT) return c.json({ error: "尚未設定 TELEGRAM_BOT_TOKEN 或 TELEGRAM_CHAT_ID" }, 400);
  const r = await fetch(`https://api.telegram.org/bot${TG_TOKEN}/sendMessage`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: TG_CHAT, text: "【測試通知】關鍵字主控台已連上 Telegram，客戶送出選字時會在這裡通知你。" }) });
  const j: any = await r.json().catch(() => ({}));
  return j.ok ? c.json({ ok: true }) : c.json({ error: "Telegram 回應：" + (j.description || r.status) }, 400);
});

// ---------- client ----------
async function clientByToken(token: string) {
  const [cl] = await sql`SELECT * FROM clients WHERE token=${token} AND archived=false`;
  return cl || null;
}
app.post("/api/c/:token/pin", async c => {
  const token = c.req.param("token"); const cl = await clientByToken(token);
  if (!cl) return c.json({ error: "連結無效" }, 404);
  const f = pinFails.get(token);
  if (f && f.until > Date.now()) return c.json({ error: "嘗試次數過多，請 10 分鐘後再試" }, 429);
  const { pin } = await c.req.json().catch(() => ({}));
  if (!cl.pin_hash || typeof pin !== "string" || !(await Bun.password.verify(pin, cl.pin_hash))) {
    const n = (f?.n || 0) + 1; pinFails.set(token, { n, until: n >= 5 ? Date.now() + 10 * 60e3 : 0 });
    return c.json({ error: "PIN 碼錯誤" }, 401);
  }
  pinFails.delete(token);
  const exp = String(Date.now() + 30 * 864e5);
  setCookie(c, "c_" + cl.id.slice(0, 8), exp + "." + await hmac("c." + cl.id + "." + exp + "." + (cl.pin_hash || "").slice(-12)), { ...COOKIE_OPTS, maxAge: 30 * 86400 });
  return c.json({ ok: true });
});
async function clientGuard(c: any) {
  const cl = await clientByToken(c.req.param("token"));
  if (!cl) return { err: c.json({ error: "連結無效" }, 404) };
  if (!(await clientCookieOk(c, cl)) && !(await adminOk(c))) return { err: c.json({ error: "pin" }, 401) };
  return { cl };
}
app.get("/api/c/:token/data", async c => {
  const g = await clientGuard(c); if (g.err) return g.err;
  const d = await loadClientFull(g.cl.id); if (!d) return c.json({ error: "not found" }, 404);
  await sql`UPDATE clients SET last_client_at=now() WHERE id=${g.cl.id}`;
  const cur = currentPeriod(d.periods);
  const pastPeriods = d.periods.filter((p: any) => cur && p.id !== cur.id);
  const pastMap: Record<string, string> = {};
  for (const s of d.sels) { const p = pastPeriods.find((x: any) => x.id === s.period_id); if (p) pastMap[s.keyword_id] = p.name; }
  const curSel = cur ? d.sels.filter((s: any) => s.period_id === cur.id).map((s: any) => s.keyword_id) : [];
  return c.json({
    name: d.client.name, report: d.client.report, interview: d.client.interview,
    period: cur ? { id: cur.id, name: cur.name, quota: (await periodLimit(d.client, d.periods, cur)).limit, status: cur.status, submitted_at: cur.submitted_at } : null,
    contract: d.client.contract_total ?? null, pastCount: cur ? (await periodLimit(d.client, d.periods, cur)).past : 0,
    history: pastPeriods.map((p: any) => ({ name: p.name, count: d.sels.filter((s: any) => s.period_id === p.id).length })),
    cats: d.cats.map((x: any) => ({ id: x.id, name: x.name, note: x.note })),
    kws: d.kws.filter((k: any) => !k.hidden).map((k: any) => ({ id: k.id, c: k.category_id, kw: k.kw, vol: k.vol, hi: k.hi, comp: k.comp, intent: k.intent, content: k.content, note: k.note, path: k.path, rec: k.rec })),
    selected: curSel, past: pastMap,
  });
});
app.post("/api/c/:token/select", async c => {
  const g = await clientGuard(c); if (g.err) return g.err;
  const { keyword_id, selected } = await c.req.json();
  const periods = await sql`SELECT * FROM periods WHERE client_id=${g.cl.id} ORDER BY sort, created_at`;
  const cur = currentPeriod(periods);
  if (!cur) return c.json({ error: "目前沒有開放選字的期別" }, 400);
  if (cur.status !== "open") return c.json({ error: "這一期已送出，無法再修改" }, 400);
  const [k] = await sql`SELECT id FROM keywords WHERE id=${keyword_id} AND client_id=${g.cl.id} AND hidden=false`;
  if (!k) return c.json({ error: "關鍵字不存在" }, 400);
  if (selected) {
    const [past] = await sql`SELECT p.name FROM selections s JOIN periods p ON p.id=s.period_id WHERE s.keyword_id=${keyword_id} AND p.id<>${cur.id} LIMIT 1`;
    if (past) return c.json({ error: `這個字已在${past.name}選過` }, 400);
    const [n] = await sql`SELECT count(*)::int AS n FROM selections WHERE period_id=${cur.id}`;
    const lim = await periodLimit(g.cl, periods, cur);
    if (n.n >= lim.limit) return c.json({ error: "已達合約數量上限" }, 400);
    await sql`INSERT INTO selections (period_id,keyword_id,by_whom) VALUES (${cur.id},${keyword_id},'client') ON CONFLICT DO NOTHING`;
  } else await sql`DELETE FROM selections WHERE period_id=${cur.id} AND keyword_id=${keyword_id}`;
  const [n2] = await sql`SELECT count(*)::int AS n FROM selections WHERE period_id=${cur.id}`;
  return c.json({ ok: true, count: n2.n });
});
app.post("/api/c/:token/submit", async c => {
  const g = await clientGuard(c); if (g.err) return g.err;
  const periods = await sql`SELECT * FROM periods WHERE client_id=${g.cl.id} ORDER BY sort, created_at`;
  const cur = currentPeriod(periods);
  if (!cur || cur.status !== "open") return c.json({ error: "目前沒有可送出的期別" }, 400);
  const sel = await sql`SELECT k.kw FROM selections s JOIN keywords k ON k.id=s.keyword_id WHERE s.period_id=${cur.id} ORDER BY k.vol DESC NULLS LAST`;
  if (!sel.length) return c.json({ error: "尚未選擇任何關鍵字" }, 400);
  await sql`UPDATE periods SET status='submitted', submitted_at=now() WHERE id=${cur.id}`;
  const link = PUBLIC_URL ? `\n▸ 主控台：${PUBLIC_URL}/admin#c/${g.cl.id}` : "";
  const lim = await periodLimit(g.cl, periods, cur);
  await notify(`【關鍵字已送出】${g.cl.name}\n${cur.name}：本期已選 ${sel.length}／本期可選 ${lim.limit}${g.cl.contract_total != null ? `（合約總數 ${g.cl.contract_total}，過往已選 ${lim.past}）` : ""}\n◆ ${sel.map((r: any) => r.kw).join("、")}${link}`);
  return c.json({ ok: true });
});
app.put("/api/c/:token/interview", async c => {
  const g = await clientGuard(c); if (g.err) return g.err;
  const b = await c.req.json(); const iv = g.cl.interview || { sections: [] };
  // clients may only change answers / table cells / status of existing questions
  for (const upd of (b.items || [])) {
    const sec = iv.sections?.[upd.si]; const it = sec?.items?.[upd.ii];
    if (!it) continue;
    if (it.type === "text" && typeof upd.a === "string") it.a = upd.a.slice(0, 5000);
    if (it.type === "table" && Array.isArray(upd.rows)) it.rows = upd.rows.slice(0, 60).map((r: any) => (Array.isArray(r) ? r : []).slice(0, it.cols.length).map((x: any) => String(x ?? "").slice(0, 1000)));
    const filled = it.type === "text" ? !!(it.a || "").trim() : (it.rows || []).some((r: any[]) => r.some(x => String(x).trim()));
    if (filled) it.st = "done"; else if (it.st === "done") it.st = "empty";
  }
  await sql`UPDATE clients SET interview=${(iv) as any}::jsonb, last_client_at=now() WHERE id=${g.cl.id}`;
  return c.json({ ok: true });
});

// ---------- pages ----------
app.get("/admin", c => c.html(ADMIN_HTML));
app.get("/c/:token", async c => {
  const cl = await clientByToken(c.req.param("token"));
  if (!cl) return c.html(page("連結無效", `<main class="wrap narrow"><h1>連結無效</h1><p class="muted">請向您的顧問確認網址是否正確。</p></main>`), 404);
  return c.html(CLIENT_HTML.replace("__TITLE__", escHtml(cl.name)));
});
function escHtml(s: string) { return String(s).replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" } as any)[ch]); }

function defaultInterview(name: string) {
  const T = (q: string, hint = "") => ({ type: "text", q, a: "", st: "empty", src: "", hint, kw: "" });
  const TB = (q: string, cols: string[], n: number, hint = "") => ({ type: "table", q, cols, rows: Array.from({ length: n }, () => cols.map(() => "")), st: "empty", src: "", hint, kw: "" });
  return { meta: { client: name, by: "MaKarma 瑪卡鎷行銷", title: "產業深度訪談表", code: "FORM-SEO-INTV-A", date: "", intro: "請用平常跟客戶講話的方式回答，愈口語愈有用。不確定的先空著，我們會在訪談時一起補。" }, glossary: [],
    sections: [
      { id: "s1", no: "壹", title: "基本資料", intro: "", items: [T("公司／品牌名稱"), T("填表人姓名／職稱"), T("官方網站"), T("銷售通路", "官網、電商平台等，請附連結"), T("實體據點"), T("社群與平台帳號")] },
      { id: "s2", no: "貳", title: "品牌與商品", intro: "先填共同特色，後面每項商品只需要寫不一樣的地方。", items: [T("1. 全品牌共同特色", "原料、製程、產地、品質標準、認證等"), TB("2. 主要商品", ["商品名稱", "與共同特色的差異", "使用方式", "誰會買", "價格"], 3)] },
      { id: "s3", no: "參", title: "我們跟別人差在哪", intro: "這一節是整份表最重要的部分。", items: [TB("3. 與同業的差異對照", ["比較項目", "我們", "一般同業"], 4), T("4. 外行人最容易搞錯的三件事"), TB("5. 客人最常問的問題", ["客人問", "您怎麼回答"], 3), T("6. 客人買過之後，最常回頭跟您說哪一句話？"), T("7. 比價之後選了別家，通常是什麼原因？"), T("8. 什麼樣的客人其實不適合貴公司？")] },
      { id: "s4", no: "肆", title: "撰寫時的注意事項", intro: "", items: [T("一定要避開的字眼或說法"), T("希望被強調的說法"), T("不可以提到的品牌"), T("可以列入推薦的品牌或通路"), T("法規上需要留意的用語"), T("近期活動或檔期")] },
      { id: "s5", no: "伍", title: "待確認事項", intro: "", items: [TB("待確認清單", ["待確認事項", "由誰回覆", "預計回覆日", "備註"], 3)] },
      { id: "s6", no: "陸", title: "其他補充", intro: "", items: [T("任何您覺得我們應該知道、但上面沒問到的事")] },
    ] };
}

const ADMIN_HTML = "<!DOCTYPE html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\">\n<title>關鍵字主控台｜MaKarma</title>\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link href=\"https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Noto+Sans+TC:wght@400;500;700;900&display=swap\" rel=\"stylesheet\">\n<style>:root{--navy:#071b2e;--navy2:#0d3453;--ink:#172433;--muted:#566676;--cyan:#28adc7;--orange:#f47a21;--green:#1f8a5b;--red:#c0392b;--pale:#f2f7fa;--line:#dce6ed;--bg:#fff;--card:#fff;--input:#fff;\n--font:\"IBM Plex Sans\",\"Noto Sans TC\",\"PingFang TC\",\"Microsoft JhengHei\",system-ui,sans-serif;color-scheme:light}\n@media (prefers-color-scheme:dark){:root{--ink:#e4edf4;--muted:#9fb1c1;--pale:#0f2335;--line:#223a50;--bg:#081624;--card:#0d2033;--navy:#050f1a;--navy2:#0a2a44;--input:#0a1a2a;color-scheme:dark}}\n*,*::before,*::after{box-sizing:border-box}\nhtml{scroll-padding-top:120px}\nbody{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:15.5px;line-height:1.65;-webkit-font-smoothing:antialiased}\na{color:inherit}\nbutton{font:inherit;cursor:pointer}\n:focus-visible{outline:2px solid var(--cyan);outline-offset:2px;border-radius:4px}\n.wrap{max-width:1180px;margin:0 auto;padding:0 20px}\n.narrow{max-width:460px}\nh1,h2,h3{line-height:1.3;margin:0}\nh1{font-size:clamp(24px,3vw,32px)} h2{font-size:22px} h3{font-size:17px}\n.muted{color:var(--muted)} .small{font-size:13px}\n.btn{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:7px 14px;border-radius:9px;font-size:14px;white-space:nowrap}\n.btn:hover{border-color:var(--cyan)}\n.btn.primary{background:var(--orange);border-color:var(--orange);color:#fff;font-weight:600}\n.btn.dark{background:var(--navy2);border-color:var(--navy2);color:#fff}\n.btn.danger{color:var(--red)} .btn.armed{background:var(--red);border-color:var(--red);color:#fff}\n.btn:disabled{opacity:.45;cursor:default}\n.btn.sm{padding:4px 10px;font-size:13px}\ninput.in,select.in,textarea.in{border:1px solid var(--line);background:var(--input);color:var(--ink);border-radius:8px;padding:7px 10px;font:inherit;font-size:14.5px;width:100%}\ntextarea.in{resize:vertical;min-height:4em;line-height:1.6}\ninput.in.n{text-align:right}\n.top{background:var(--navy);color:#e8f1f7}\n.top .wrap{display:flex;align-items:center;gap:16px;min-height:60px;flex-wrap:wrap;padding-top:8px;padding-bottom:8px}\n.brand{font-weight:700;letter-spacing:.02em}\n.brand small{display:block;font-size:12px;font-weight:500;color:#8fb3c9;letter-spacing:.04em}\n.tabs{display:flex;gap:4px;background:rgba(255,255,255,.08);padding:3px;border-radius:10px;margin-left:auto;flex-wrap:wrap}\n.tabs button{border:0;background:transparent;color:#b9ccda;padding:6px 12px;border-radius:8px;font-size:14px;font-weight:600}\n.tabs button[aria-selected=\"true\"]{background:#fff;color:var(--navy)}\n.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}\n.chip{display:inline-block;font-size:12.5px;font-weight:600;padding:1px 8px;border-radius:6px;white-space:nowrap;border:1px solid var(--line);color:var(--muted)}\n.chip.rec{background:var(--orange);border-color:var(--orange);color:#fff}\n.chip.past{background:var(--pale);color:var(--muted)}\n.chip.ok{background:var(--green);border-color:var(--green);color:#fff}\n.chip.open{background:color-mix(in srgb,var(--cyan) 20%,transparent);border-color:transparent;color:var(--ink)}\n.tbl-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}\ntable{border-collapse:collapse;width:100%;font-size:14.5px}\nth,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}\nth{font-size:12.5px;color:var(--muted);font-weight:600;background:var(--pale);white-space:nowrap;position:sticky;top:0}\ntr:last-child td{border-bottom:0}\ntd.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}\n.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--navy2);color:#fff;padding:10px 18px;border-radius:10px;font-size:14.5px;z-index:99;max-width:92vw;box-shadow:0 8px 24px rgba(0,0,0,.2)}\n.toast.err{background:var(--red)}\n.gate{min-height:100vh;display:grid;place-items:center;background:var(--navy);padding:20px}\n.gate .card{width:100%;max-width:380px}\n.gate h1{font-size:22px;margin-bottom:6px}\n.gate input{font-size:22px;letter-spacing:.3em;text-align:center}\n.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}\n.grow{flex:1}\n.empty{border:1px dashed var(--line);border-radius:12px;padding:18px;color:var(--muted);text-align:center}\n[hidden]{display:none!important}\n\nmain{padding:24px 0 80px}\n.list{display:grid;gap:0;border-top:2px solid var(--ink)}\n.li{display:grid;grid-template-columns:minmax(0,2fr) 1.3fr 1.2fr 1fr auto;gap:14px;align-items:center;padding:14px 4px;border-bottom:1px solid var(--line);cursor:pointer}\n.li:hover{background:var(--pale)}\n.li b{font-size:16px}\n.bar2{height:6px;background:var(--pale);border-radius:3px;overflow:hidden;margin-top:4px}.bar2 i{display:block;height:100%;background:var(--cyan)}\n.sub{display:flex;gap:4px;border-bottom:1px solid var(--line);margin:18px 0 18px;flex-wrap:wrap}\n.sub button{border:0;background:transparent;padding:9px 14px;font-weight:600;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px}\n.sub button[aria-selected=\"true\"]{color:var(--ink);border-bottom-color:var(--orange)}\n.linkbox{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:var(--pale);padding:10px 14px;border-radius:10px;font-size:14px}\n.linkbox code{font-family:var(--font);word-break:break-all}\ntable.ed td{padding:4px 6px}\ntable.ed input.in,table.ed select.in{padding:5px 7px;font-size:13.5px}\n.catrow{display:grid;grid-template-columns:2fr 3fr auto auto;gap:8px;align-items:center;margin-bottom:6px}\n.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}\n.fld label{display:block;font-size:12.5px;color:var(--muted);margin-bottom:3px}\n.q-ed{border-bottom:1px solid var(--line);padding:12px 0;display:grid;gap:6px}\n.q-ed .r{display:grid;grid-template-columns:2fr 1fr 9em auto;gap:6px}\ntr.sel td{background:color-mix(in srgb,var(--orange) 8%,transparent)}\n.stick{position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0;border-bottom:1px solid var(--line)}\n.modebar{display:flex;gap:4px;background:var(--pale);border:1px solid var(--line);border-radius:10px;padding:3px}\n.modebar button{border:0;background:transparent;color:var(--muted);padding:5px 10px;border-radius:8px;font-size:13px;font-weight:600}\n.modebar button[aria-selected=\"true\"]{background:var(--card);color:var(--ink);box-shadow:0 1px 3px rgba(0,0,0,.06)}\n.kw-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}\n.kw-card{border:1px solid var(--line);border-radius:14px;background:var(--card);padding:14px;display:grid;gap:10px}\n.kw-card.sel{border-color:color-mix(in srgb,var(--orange) 55%,var(--line));box-shadow:0 0 0 3px color-mix(in srgb,var(--orange) 10%,transparent)}\n.kw-card.hidden{opacity:.55}\n.kw-head{display:flex;gap:10px;align-items:flex-start}\n.kw-head input[type=checkbox]{margin-top:6px}\n.kw-meta{display:flex;gap:8px;flex-wrap:wrap;align-items:center}\n.kw-fields{display:grid;grid-template-columns:1fr 1fr;gap:8px}\n.kw-fields .wide{grid-column:1/-1}\n.helpbox{background:var(--pale);border:1px solid var(--line);border-radius:12px;padding:12px 14px}\n@media (max-width:760px){.li{grid-template-columns:1fr 1fr}.grid2,.catrow,.q-ed .r,.kw-fields{grid-template-columns:1fr}.kw-cards{grid-template-columns:1fr}}\n</style></head><body>\n<div id=\"root\"></div>\n<script>\nconst $=s=>document.querySelector(s);\nconst esc=s=>String(s==null?'':s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\nconst fmt=(v,d=0)=>v==null||v===''?'':Number(v).toLocaleString('zh-TW',{minimumFractionDigits:d,maximumFractionDigits:d});\nconst fdate=s=>s?new Date(s).toLocaleString('zh-TW',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'}):'—';\nfunction toast(m,err){const t=document.createElement('div');t.className='toast'+(err?' err':'');t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}\nasync function api(p,opt={}){const r=await fetch(p,{credentials:'same-origin',headers:{'content-type':'application/json'},...opt});const j=await r.json().catch(()=>({}));if(r.status===401&&p!=='/api/admin/login'){showLogin();throw new Error('請重新登入');}if(!r.ok)throw new Error(j.error||'錯誤');return j;}\nfunction armed(b,label,fn){if(b.dataset.armed!=='1'){const o=b.textContent;b.dataset.armed='1';b.textContent=label;b.classList.add('armed');setTimeout(()=>{if(b.isConnected){b.dataset.armed='';b.textContent=o;b.classList.remove('armed');}},3500);return;}fn();}\nlet ME=null, C=null, sub='kw', periodId=null, catF='all', qF='', picked=new Set(), sortK='vol', kwMode='cards';\n\nfunction shell(inner,title){return `<header class=\"top\"><div class=\"wrap\"><div class=\"brand\">關鍵字主控台<small>MaKarma 瑪卡鎷行銷</small></div><div class=\"grow\"></div>${title||''}<button class=\"btn sm\" id=\"logout\" style=\"background:transparent;color:#b9ccda;border-color:#2c5570\">登出</button></div></header><main><div class=\"wrap\">${inner}</div></main>`;}\nfunction bindShell(){const l=$('#logout');if(l)l.onclick=async()=>{await api('/api/admin/logout',{method:'POST'});showLogin();};}\nfunction showLogin(){$('#root').innerHTML=`<div class=\"gate\"><form class=\"card\" id=\"lf\"><h1>關鍵字主控台</h1><p class=\"muted\">請輸入管理密碼</p><input class=\"in\" type=\"password\" id=\"pw\" autocomplete=\"current-password\" style=\"letter-spacing:normal;font-size:16px;text-align:left\" aria-label=\"管理密碼\"><p id=\"le\" class=\"small\" style=\"color:var(--red);min-height:1.5em\"></p><button class=\"btn primary\" style=\"width:100%\">登入</button></form></div>`;\n  $('#pw').focus();$('#lf').onsubmit=async e=>{e.preventDefault();try{await api('/api/admin/login',{method:'POST',body:JSON.stringify({password:$('#pw').value})});route();}catch(err){$('#le').textContent=err.message;}};}\nasync function route(){\n  try{ME=await api('/api/admin/me');}catch(e){return;}\n  const h=location.hash.slice(1);\n  if(h.startsWith('c/'))openClient(h.slice(2)); else listClients();\n}\nwindow.onhashchange=route;\n\n/* ---------- client list ---------- */\nasync function listClients(){\n  const cls=await api('/api/admin/clients');\n  $('#root').innerHTML=shell(`\n   <div class=\"row\" style=\"margin-bottom:16px\"><h1 class=\"grow\">所有客戶</h1>${ME.notion?'<button class=\"btn\" id=\"syncAll\">從 Notion 同步已選字</button>':''}${ME.telegram?'<button class=\"btn\" id=\"tgTest\">發送測試通知</button>':''}<button class=\"btn\" id=\"newHy\">新增華邑</button><button class=\"btn primary\" id=\"newC\">新增客戶</button></div>\n   <div id=\"syncOut\"></div>\n   ${ME.telegram?'':'<p class=\"small\" style=\"color:var(--orange)\">▸ 尚未設定 Telegram 通知：請在 Railway Variables 新增 TELEGRAM_BOT_TOKEN 與 TELEGRAM_CHAT_ID。</p>'}\n   <form class=\"card\" id=\"nf\" hidden style=\"margin-bottom:18px\"><div class=\"grid2\"><div class=\"fld\"><label>客戶名稱</label><input class=\"in\" name=\"name\" required></div><div class=\"fld\"><label>客戶 PIN 碼（4–6 位數字）</label><input class=\"in\" name=\"pin\" inputmode=\"numeric\" required></div><div class=\"fld\"><label>第一期合約數</label><input class=\"in n\" name=\"quota\" type=\"number\" value=\"20\" min=\"1\"></div></div><div class=\"row\" style=\"margin-top:12px\"><button class=\"btn primary\">建立</button><button type=\"button\" class=\"btn\" id=\"nfc\">取消</button></div></form>\n   <div class=\"list\">${cls.map(c=>{const s=c.stats,p=s.period;return `<div class=\"li\" data-id=\"${c.id}\" tabindex=\"0\" role=\"link\">\n     <div><b>${esc(c.name)}</b>${c.archived?' <span class=\"chip\">封存</span>':''}<div class=\"small muted\">${s.keywords} 組候選字｜${s.periods} 期</div></div>\n     <div>${p?`<div class=\"small\">${esc(p.name)}${s.contract!=null?'｜合約 '+s.contract+'，過往 '+s.past:''}</div><div>本期已選 <b>${s.selected}</b>／${s.limit}</div><div class=\"bar2\"><i style=\"width:${s.limit?Math.min(100,s.selected/s.limit*100):0}%\"></i></div>`:'—'}</div>\n     <div>${p?(p.status==='open'?'<span class=\"chip open\">選字中</span>':'<span class=\"chip ok\">已送出</span> <span class=\"small muted\">'+fdate(p.submitted_at)+'</span>'):''}</div>\n     <div class=\"small muted\">客戶最後造訪<br>${fdate(c.last_client_at)}</div><div class=\"small muted\">▸</div></div>`}).join('')||'<div class=\"empty\">尚無客戶</div>'}</div>`);\n  bindShell();\n  document.querySelectorAll('.li').forEach(el=>{el.onclick=()=>location.hash='c/'+el.dataset.id;el.onkeydown=e=>{if(e.key==='Enter')el.click();};});\n  const sa=$('#syncAll');if(sa)sa.onclick=async()=>{sa.disabled=true;sa.textContent='同步中…';try{const r=await api('/api/admin/notion-sync-all',{method:'POST'});\n    $('#syncOut').innerHTML='<div class=\"card\" style=\"margin-bottom:16px\"><b>Notion 同步結果</b><ul class=\"small\" style=\"margin:8px 0 0;padding-left:1.2em\">'+r.map(x=>'<li>'+esc(x.name)+'：'+(x.ok?`合約 ${x.total??'—'} 組；新標記已選 ${x.marked} 組、新增 ${x.added} 組${x.onlyInSystem.length?'；系統有但 Notion 沒有：'+x.onlyInSystem.map(esc).join('、'):''}`:'<span style=\"color:var(--red)\">'+esc(x.error)+'</span>')+'</li>').join('')+'</ul></div>';}catch(e){toast(e.message,true);}sa.disabled=false;sa.textContent='從 Notion 同步已選字';};\n  const tt=$('#tgTest');if(tt)tt.onclick=()=>api('/api/admin/telegram-test',{method:'POST'}).then(()=>toast('已發送，請到 Telegram 確認')).catch(e=>toast(e.message,true));\n  const hy=$('#newHy');if(hy)hy.onclick=async()=>{const exists=cls.find(c=>/華邑/.test(c.name));if(exists){location.hash='c/'+exists.id;return;}const pin=prompt('請設定華邑食品的客戶 PIN 碼（4–6 位數字）');if(!pin)return;try{const r=await api('/api/admin/clients',{method:'POST',body:JSON.stringify({name:'華邑食品',pin,quota:20})});toast('已新增華邑食品');location.hash='c/'+r.id;}catch(e){toast(e.message,true);}};\n  $('#newC').onclick=()=>{$('#nf').hidden=false;$('#nf [name=name]').focus();};$('#nfc').onclick=()=>$('#nf').hidden=true;\n  $('#nf').onsubmit=async e=>{e.preventDefault();const f=new FormData(e.target);try{const r=await api('/api/admin/clients',{method:'POST',body:JSON.stringify(Object.fromEntries(f))});location.hash='c/'+r.id;}catch(err){toast(err.message,true);}};\n}\n\n/* ---------- client detail ---------- */\nasync function openClient(id,keep){\n  C=await api('/api/admin/clients/'+id);\n  if(!keep){periodId=null;catF='all';qF='';picked=new Set();}\n  if(!periodId||!C.periods.find(p=>p.id===periodId))periodId=C.periods.length?C.periods[C.periods.length-1].id:null;\n  const url=(ME.publicUrl||location.origin)+'/c/'+C.client.token;\n  $('#root').innerHTML=shell(`\n   <p class=\"small\"><a href=\"#\" id=\"back\">◂ 所有客戶</a></p>\n   <div class=\"row\"><h1 class=\"grow\">${esc(C.client.name)}</h1>${ME.notion?'<button class=\"btn\" id=\"nSync\">從 Notion 同步</button>':''}<a class=\"btn\" href=\"/c/${C.client.token}\" target=\"_blank\" rel=\"noopener\">以客戶畫面開啟</a></div>\n   <div class=\"linkbox\" style=\"margin-top:12px\"><span class=\"muted\">客戶連結</span><code id=\"url\">${esc(url)}</code><button class=\"btn sm\" id=\"copy\">複製</button><span class=\"muted small\">客戶需輸入 PIN 碼才能進入</span></div>\n   <div class=\"sub\" role=\"tablist\">${[['kw','關鍵字'],['period','期別與合約'],['report','報告內容'],['iv','訪談表'],['set','設定']].map(([k,l])=>`<button data-s=\"${k}\" aria-selected=\"${sub===k}\">${l}</button>`).join('')}</div>\n   <div id=\"body\"></div>`);\n  bindShell();\n  $('#back').onclick=e=>{e.preventDefault();location.hash='';};\n  const ns=$('#nSync');if(ns)ns.onclick=async()=>{ns.disabled=true;try{const r=await api('/api/admin/clients/'+C.client.id+'/notion-sync',{method:'POST'});toast(`Notion「${r.project}」：合約 ${r.contract_total??'—'} 組，新標記 ${r.marked.length} 組${r.onlyInSystem.length?'；系統多出：'+r.onlyInSystem.join('、'):''}`);reload();}catch(e){toast(e.message,true);ns.disabled=false;}};\n  $('#copy').onclick=()=>{navigator.clipboard.writeText(url).then(()=>toast('已複製連結'));};\n  document.querySelectorAll('[data-s]').forEach(b=>b.onclick=()=>{sub=b.dataset.s;document.querySelectorAll('[data-s]').forEach(x=>x.setAttribute('aria-selected',x===b));renderSub();});\n  renderSub();\n}\nfunction renderSub(){({kw:subKw,period:subPeriod,report:subReport,iv:subIv,set:subSet})[sub]();}\nconst reload=()=>openClient(C.client.id,true);\n\n/* keywords */\nfunction catName(id){const c=C.cats.find(x=>x.id===id);return c?c.name:'未分類';}\nfunction subKw(){\n  const P=C.periods.find(p=>p.id===periodId);\n  const selSet=new Set(C.sels.filter(s=>s.period_id===periodId).map(s=>s.keyword_id));\n  const pastSet={};C.sels.filter(s=>s.period_id!==periodId).forEach(s=>{pastSet[s.keyword_id]=C.periods.find(p=>p.id===s.period_id)?.name;});\n  const qq=qF.trim().toLowerCase();\n  let ks=C.kws.filter(k=>(catF==='all'||(catF===''?!k.category_id:k.category_id===catF))&&(!qq||k.kw.toLowerCase().includes(qq)||(k.note||'').toLowerCase().includes(qq)||(k.intent||'').toLowerCase().includes(qq)||(k.content||'').toLowerCase().includes(qq)));\n  ks.sort((a,b)=>sortK==='vol'?((b.vol??-1)-(a.vol??-1)):sortK==='hi'?((b.hi??-1)-(a.hi??-1)):sortK==='sel'?((selSet.has(b.id))-(selSet.has(a.id))):a.kw.localeCompare(b.kw));\n  const catOpts=(v)=>`<option value=\"\">未分類</option>`+C.cats.map(c=>`<option value=\"${c.id}\" ${c.id===v?'selected':''}>${esc(c.name)}</option>`).join('');\n  const flag=k=>`${pastSet[k.id]?`<span class=\"chip past\">已在 ${esc(pastSet[k.id])}</span>`:`<label class=\"small\"><input type=\"checkbox\" data-sel=\"${k.id}\" ${selSet.has(k.id)?'checked':''}> 本期選用</label>`}${k.hidden?' <span class=\"chip\">隱藏</span>':''}${k.rec?' <span class=\"chip rec\">顧問推薦</span>':''}`;\n  const tableView=`<div class=\"tbl-scroll\"><table class=\"ed\"><thead><tr><th><input type=\"checkbox\" id=\"pickAll\" aria-label=\"全選\"></th><th>本期選用</th><th>關鍵字</th><th>分類</th><th class=\"num\">月搜尋量</th><th class=\"num\">頁首出價上限</th><th>為什麼選這個字</th><th>建議文章</th><th>可導向</th><th>備註</th><th>推薦</th></tr></thead><tbody>\n  ${ks.map(k=>`<tr class=\"${selSet.has(k.id)?'sel':''}\" ${k.hidden?'style=\"opacity:.45\"':''}><td><input type=\"checkbox\" data-pick=\"${k.id}\" ${picked.has(k.id)?'checked':''} aria-label=\"選取列\"></td>\n   <td>${pastSet[k.id]?`<span class=\"chip past\">${esc(pastSet[k.id])}</span>`:`<input type=\"checkbox\" data-sel=\"${k.id}\" ${selSet.has(k.id)?'checked':''} aria-label=\"本期選用\">`}${k.hidden?' <span class=\"chip\">隱藏</span>':''}</td>\n   <td><input class=\"in\" data-f=\"kw\" data-k=\"${k.id}\" value=\"${esc(k.kw)}\" style=\"min-width:12em\"></td>\n   <td><select class=\"in\" data-f=\"category_id\" data-k=\"${k.id}\" style=\"min-width:8em\">${catOpts(k.category_id)}</select></td>\n   <td><input class=\"in n\" data-f=\"vol\" data-k=\"${k.id}\" type=\"number\" value=\"${k.vol??''}\" style=\"width:6.5em\"></td>\n   <td><input class=\"in n\" data-f=\"hi\" data-k=\"${k.id}\" type=\"number\" step=\"0.01\" value=\"${k.hi??''}\" style=\"width:6.5em\"></td>\n   <td><input class=\"in\" data-f=\"intent\" data-k=\"${k.id}\" value=\"${esc(k.intent)}\" style=\"min-width:10em\"></td>\n   <td><input class=\"in\" data-f=\"content\" data-k=\"${k.id}\" value=\"${esc(k.content)}\" style=\"min-width:10em\"></td>\n   <td><input class=\"in\" data-f=\"path\" data-k=\"${k.id}\" value=\"${esc(k.path)}\" style=\"min-width:10em\"></td>\n   <td><input class=\"in\" data-f=\"note\" data-k=\"${k.id}\" value=\"${esc(k.note)}\" style=\"min-width:8em\"></td>\n   <td><input type=\"checkbox\" data-f=\"rec\" data-k=\"${k.id}\" ${k.rec?'checked':''} aria-label=\"顧問推薦\"></td></tr>`).join('')}\n  </tbody></table></div>`;\n  const cardView=`<div class=\"kw-cards\">${ks.map(k=>`<section class=\"kw-card ${selSet.has(k.id)?'sel':''} ${k.hidden?'hidden':''}\">\n    <div class=\"kw-head\"><input type=\"checkbox\" data-pick=\"${k.id}\" ${picked.has(k.id)?'checked':''} aria-label=\"選取這組關鍵字\"><div class=\"grow\"><label class=\"small muted\">關鍵字</label><input class=\"in\" data-f=\"kw\" data-k=\"${k.id}\" value=\"${esc(k.kw)}\"></div></div>\n    <div class=\"kw-meta\">${flag(k)}<label class=\"small\"><input type=\"checkbox\" data-f=\"rec\" data-k=\"${k.id}\" ${k.rec?'checked':''}> 顧問推薦</label></div>\n    <div class=\"kw-fields\"><div class=\"fld\"><label>分類</label><select class=\"in\" data-f=\"category_id\" data-k=\"${k.id}\">${catOpts(k.category_id)}</select></div><div class=\"fld\"><label>月搜尋量</label><input class=\"in n\" data-f=\"vol\" data-k=\"${k.id}\" type=\"number\" value=\"${k.vol??''}\"></div><div class=\"fld\"><label>頁首出價上限</label><input class=\"in n\" data-f=\"hi\" data-k=\"${k.id}\" type=\"number\" step=\"0.01\" value=\"${k.hi??''}\"></div><div class=\"fld\"><label>可導向頁面</label><input class=\"in\" data-f=\"path\" data-k=\"${k.id}\" value=\"${esc(k.path)}\"></div><div class=\"fld wide\"><label>為什麼選這個字</label><textarea class=\"in\" data-f=\"intent\" data-k=\"${k.id}\">${esc(k.intent)}</textarea></div><div class=\"fld wide\"><label>建議文章</label><textarea class=\"in\" data-f=\"content\" data-k=\"${k.id}\">${esc(k.content)}</textarea></div><div class=\"fld wide\"><label>內部備註</label><textarea class=\"in\" data-f=\"note\" data-k=\"${k.id}\">${esc(k.note)}</textarea></div></div>\n  </section>`).join('')||'<div class=\"empty\">沒有符合條件的關鍵字</div>'}</div>`;\n  $('#body').innerHTML=`\n  <div class=\"helpbox\" style=\"margin-bottom:14px\"><b>編輯提示</b><div class=\"small muted\">卡片模式適合逐題編修，修改欄位後離開欄位會自動儲存；需要大量貼資料或快速掃描時，可切回表格模式。</div></div>\n  <details class=\"card\" style=\"margin-bottom:14px\"><summary><b>分類管理</b> <span class=\"muted small\">（${C.cats.length} 個分類，客戶頁依此分組）</span></summary><div style=\"margin-top:12px\">\n   ${C.cats.map((c,i)=>`<div class=\"catrow\"><input class=\"in\" data-cn=\"${c.id}\" value=\"${esc(c.name)}\" aria-label=\"分類名稱\"><input class=\"in\" data-cnote=\"${c.id}\" value=\"${esc(c.note)}\" placeholder=\"分類說明（客戶會看到）\" aria-label=\"分類說明\"><span class=\"small muted\">${C.kws.filter(k=>k.category_id===c.id).length} 組</span><button class=\"btn sm danger\" data-cdel=\"${c.id}\">刪除</button></div>`).join('')}\n   <div class=\"row\" style=\"margin-top:8px\"><input class=\"in\" id=\"newCat\" placeholder=\"新分類名稱\" style=\"max-width:260px\"><button class=\"btn sm\" id=\"addCat\">新增分類</button><span class=\"small muted\">刪除分類時，其中的字會移到「未分類」</span></div></div></details>\n  <details class=\"card\" style=\"margin-bottom:14px\"><summary><b>匯入關鍵字</b> <span class=\"muted small\">（Keyword Planner CSV 或直接貼上）</span></summary><div style=\"margin-top:12px\">\n   <p class=\"small muted\">可上傳 Keyword Planner 匯出的 CSV，或從試算表貼上三欄：關鍵字、月搜尋量、頁首出價上限（Tab 分隔）。已存在的字只更新數據。</p>\n   <div class=\"row\"><select class=\"in\" id=\"impCat\" style=\"max-width:220px\">${catOpts(catF!=='all'?catF:'')}</select><input type=\"file\" id=\"impFile\" accept=\".csv,.tsv,.txt\"><button class=\"btn sm\" id=\"impGo\">匯入貼上的內容</button></div>\n   <textarea class=\"in\" id=\"impText\" rows=\"4\" style=\"margin-top:8px\" placeholder=\"關鍵字&#9;月搜尋量&#9;頁首出價上限\"></textarea></div></details>\n  <div class=\"stick\"><div class=\"row\">\n   <label class=\"small muted\">檢視期別</label><select class=\"in\" id=\"pSel\" style=\"max-width:220px\">${C.periods.map(p=>`<option value=\"${p.id}\" ${p.id===periodId?'selected':''}>${esc(p.name)}（${p.status==='open'?'選字中':'已送出'}）</option>`).join('')}</select>\n   ${P?`<span>已選 <b>${selSet.size}</b>${C.client.contract_total!=null?'':'／'+P.quota}</span>`:''}\n   <select class=\"in\" id=\"cF\" style=\"max-width:180px\"><option value=\"all\">全部分類</option>${catOpts(catF).replace('value=\"\"','value=\"\"'+(catF===''?' selected':''))}</select>\n   <input class=\"in\" id=\"qF\" placeholder=\"搜尋關鍵字、備註、選字理由\" value=\"${esc(qF)}\" style=\"max-width:220px\">\n   <select class=\"in\" id=\"sK\" style=\"max-width:140px\">${[['vol','依搜尋量'],['hi','依出價'],['sel','已選優先'],['kw','依字母']].map(([k,l])=>`<option value=\"${k}\" ${sortK===k?'selected':''}>${l}</option>`).join('')}</select>\n   <div class=\"modebar\" role=\"tablist\" aria-label=\"編輯模式\"><button data-kwmode=\"cards\" aria-selected=\"${kwMode==='cards'}\">卡片</button><button data-kwmode=\"table\" aria-selected=\"${kwMode==='table'}\">表格</button></div>\n   <div class=\"grow\"></div><button class=\"btn sm dark\" id=\"addKw\">新增關鍵字</button></div>\n   <div class=\"row small\" style=\"margin-top:8px\"><span class=\"muted\">已勾選 ${picked.size} 列：</span><select class=\"in\" id=\"mvCat\" style=\"max-width:180px\">${catOpts('')}</select><button class=\"btn sm\" id=\"bMove\">移到此分類</button><button class=\"btn sm\" id=\"bHide\">隱藏</button><button class=\"btn sm\" id=\"bShow\">取消隱藏</button><button class=\"btn sm danger\" id=\"bDel\">刪除</button><span class=\"muted\">顯示 ${ks.length} 組</span></div></div>\n  ${kwMode==='cards'?cardView:tableView}`;\n  $('#pSel').onchange=e=>{periodId=e.target.value;subKw();};\n  $('#cF').onchange=e=>{catF=e.target.value;subKw();};\n  $('#qF').oninput=e=>{qF=e.target.value;clearTimeout(window._qt);window._qt=setTimeout(()=>{subKw();const el=$('#qF');el.focus();el.setSelectionRange(el.value.length,el.value.length);},300);};\n  $('#sK').onchange=e=>{sortK=e.target.value;subKw();};\n  document.querySelectorAll('[data-kwmode]').forEach(b=>b.onclick=()=>{kwMode=b.dataset.kwmode;subKw();});\n  document.querySelectorAll('[data-f]').forEach(el=>el.onchange=async()=>{const k=C.kws.find(x=>x.id===el.dataset.k);const f=el.dataset.f;const v=el.type==='checkbox'?el.checked:el.value;\n    try{await api('/api/admin/keywords/'+k.id,{method:'PATCH',body:JSON.stringify({[f]:v})});k[f]=f==='vol'||f==='hi'?(v===''?null:Number(v)):v;if(f==='category_id')k[f]=v||null;toast('已儲存');}catch(e){toast(e.message,true);}});\n  document.querySelectorAll('[data-sel]').forEach(el=>el.onchange=async()=>{try{await api('/api/admin/periods/'+periodId+'/toggle',{method:'POST',body:JSON.stringify({keyword_id:el.dataset.sel,selected:el.checked})});\n    if(el.checked)C.sels.push({period_id:periodId,keyword_id:el.dataset.sel});else C.sels=C.sels.filter(s=>!(s.period_id===periodId&&s.keyword_id===el.dataset.sel));subKw();}catch(e){toast(e.message,true);}});\n  document.querySelectorAll('[data-pick]').forEach(el=>el.onchange=()=>{el.checked?picked.add(el.dataset.pick):picked.delete(el.dataset.pick);subKw();});\n  const pa=$('#pickAll');if(pa)pa.onchange=e=>{ks.forEach(k=>e.target.checked?picked.add(k.id):picked.delete(k.id));subKw();};\n  const bulk=async(action,extra={})=>{if(!picked.size)return toast('請先勾選列',true);const r=await api('/api/admin/keywords/bulk',{method:'POST',body:JSON.stringify({ids:[...picked],action,...extra})});picked=new Set();if(r.hidden)toast(`已刪除 ${r.deleted} 組；${r.hidden} 組因過往期別選用過，改為隱藏`);reload();};\n  $('#bMove').onclick=()=>bulk('move',{category_id:$('#mvCat').value||null});\n  $('#bHide').onclick=()=>bulk('hide');$('#bShow').onclick=()=>bulk('show');\n  $('#bDel').onclick=e=>armed(e.target,'確定刪除',()=>bulk('delete'));\n  $('#addKw').onclick=async()=>{const kw=prompt('新關鍵字');if(!kw)return;await api('/api/admin/clients/'+C.client.id+'/keywords',{method:'POST',body:JSON.stringify({rows:[{kw}],category_id:catF!=='all'&&catF?catF:null})});reload();};\n  document.querySelectorAll('[data-cn]').forEach(el=>el.onchange=()=>api('/api/admin/categories/'+el.dataset.cn,{method:'PATCH',body:JSON.stringify({name:el.value})}).then(()=>{C.cats.find(c=>c.id===el.dataset.cn).name=el.value;toast('已儲存');}));\n  document.querySelectorAll('[data-cnote]').forEach(el=>el.onchange=()=>api('/api/admin/categories/'+el.dataset.cnote,{method:'PATCH',body:JSON.stringify({note:el.value})}).then(()=>toast('已儲存')));\n  document.querySelectorAll('[data-cdel]').forEach(el=>el.onclick=()=>armed(el,'確定刪除',async()=>{await api('/api/admin/categories/'+el.dataset.cdel,{method:'DELETE'});reload();}));\n  $('#addCat').onclick=async()=>{const n=$('#newCat').value.trim();if(!n)return;await api('/api/admin/clients/'+C.client.id+'/categories',{method:'POST',body:JSON.stringify({name:n})});reload();};\n  $('#impFile').onchange=async e=>{const f=e.target.files[0];if(!f)return;const rows=await parseKP(f);if(!rows)return;doImport(rows);};\n  $('#impGo').onclick=()=>{const rows=$('#impText').value.split(/\\r?\\n/).map(l=>l.split('\\t')).filter(c=>c[0]&&c[0].trim()).map(c=>({kw:c[0],vol:clean(c[1]),hi:clean(c[2])}));if(!rows.length)return toast('沒有可匯入的內容',true);doImport(rows);};\n}\nconst clean=v=>{if(v==null)return null;const s=String(v).replace(/[^0-9.]/g,'');return s===''?null:Number(s);};\nasync function doImport(rows){try{const r=await api('/api/admin/clients/'+C.client.id+'/keywords',{method:'POST',body:JSON.stringify({rows,category_id:$('#impCat').value||null})});toast(`新增 ${r.added} 組、更新 ${r.updated} 組`);reload();}catch(e){toast(e.message,true);}}\nasync function parseKP(file){const buf=await file.arrayBuffer();const u8=new Uint8Array(buf);let enc='utf-8';if(u8[0]===0xFF&&u8[1]===0xFE)enc='utf-16le';else if(u8[0]===0xFE&&u8[1]===0xFF)enc='utf-16be';else if(u8.length>3&&u8[1]===0&&u8[3]===0)enc='utf-16le';\n  const text=new TextDecoder(enc).decode(buf).replace(/^\\uFEFF/,'');const lines=text.split(/\\r?\\n/).filter(l=>l.trim());const delim=lines.some(l=>l.includes('\\t'))?'\\t':',';\n  const split=l=>{if(delim==='\\t')return l.split('\\t').map(s=>s.replace(/^\"|\"$/g,'').trim());const o=[];let cur='',q=false;for(const ch of l){if(ch==='\"')q=!q;else if(ch===','&&!q){o.push(cur.trim());cur='';}else cur+=ch;}o.push(cur.trim());return o;};\n  const hi=lines.findIndex(l=>/關鍵字|Keyword/i.test(l)&&/搜尋|search/i.test(l));if(hi<0){toast('找不到 Keyword Planner 的欄位標題',true);return null;}\n  const H=split(lines[hi]);const col=(...p)=>H.findIndex(h=>p.some(x=>x.test(h)));\n  const cK=col(/^關鍵字$/,/^Keyword$/i),cV=col(/平均每月搜尋/,/Avg\\.? monthly searches/i),cH=col(/(頁首|首頁).*高/,/Top of page bid \\(high/i);\n  const cC=H.findIndex(h=>(/^競爭/.test(h)||/^Competition$/i.test(h))&&!/索引|index/i.test(h));\n  const cm=v=>!v?'':/低|low/i.test(v)?'低':/中|medium/i.test(v)?'中':/高|high/i.test(v)?'高':'';\n  return lines.slice(hi+1).map(split).filter(c=>c[cK]).map(c=>({kw:c[cK],vol:cV>=0?clean(c[cV]):null,hi:cH>=0?clean(c[cH]):null,comp:cC>=0?cm(c[cC]):''}));}\n\n/* periods */\nfunction subPeriod(){\n  $('#body').innerHTML=`<div class=\"card\" style=\"margin-bottom:16px\"><div class=\"row\"><b>合約總字數</b><input class=\"in n\" id=\"ctTot\" type=\"number\" min=\"0\" value=\"${C.client.contract_total??''}\" style=\"max-width:120px\" placeholder=\"未設定\"><button class=\"btn sm\" id=\"ctSave\">儲存</button></div>\n   <p class=\"small muted\" style=\"margin:6px 0 0\">設定後，客戶頁會顯示「合約總數／過往已選／本期已選／剩餘」，本期可選數量＝合約總數－過往各期已選。留空則改用下方每一期各自的合約數。</p></div>\n  <div class=\"tbl-scroll\"><table class=\"ed\"><thead><tr><th>期別</th><th class=\"num\">本期合約數<br><span class=\"small\">（未設總數時使用）</span></th><th class=\"num\">已選</th><th>狀態</th><th>送出時間</th><th></th></tr></thead><tbody>\n  ${C.periods.map((p,i)=>{const n=C.sels.filter(s=>s.period_id===p.id).length;const cur=i===C.periods.length-1;return `<tr><td><input class=\"in\" data-pn=\"${p.id}\" value=\"${esc(p.name)}\">${cur?'<div class=\"small muted\">目前期別（客戶頁顯示這一期）</div>':''}</td><td><input class=\"in n\" type=\"number\" min=\"0\" data-pq=\"${p.id}\" value=\"${p.quota}\" style=\"width:6em\"></td><td class=\"num\">${n}</td>\n   <td>${p.status==='open'?'<span class=\"chip open\">選字中</span>':'<span class=\"chip ok\">已送出</span>'}</td><td class=\"small\">${fdate(p.submitted_at)}</td>\n   <td class=\"row\">${p.status==='open'?`<button class=\"btn sm\" data-lock=\"${p.id}\">鎖定</button>`:`<button class=\"btn sm\" data-unlock=\"${p.id}\">解鎖，讓客戶可再修改</button>`}${n===0?`<button class=\"btn sm danger\" data-pdel=\"${p.id}\">刪除</button>`:''}</td></tr>`}).join('')}\n  </tbody></table></div>\n  <form class=\"card\" id=\"np\" style=\"margin-top:16px\"><h3>開新一期</h3><p class=\"small muted\">新一期會成為客戶頁的目前期別；之前各期選過的字會標示「已選過」，不能重複選，也不佔新一期名額。</p>\n   <div class=\"row\"><input class=\"in\" name=\"name\" placeholder=\"例：第二期（2027 Q1）\" required style=\"max-width:280px\"><input class=\"in n\" name=\"quota\" type=\"number\" min=\"1\" value=\"20\" style=\"max-width:120px\" aria-label=\"合約數\"><button class=\"btn primary\">建立</button></div></form>`;\n  $('#ctSave').onclick=()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({contract_total:$('#ctTot').value})}).then(()=>{toast('已儲存');reload();});\n  document.querySelectorAll('[data-pn]').forEach(el=>el.onchange=()=>api('/api/admin/periods/'+el.dataset.pn,{method:'PATCH',body:JSON.stringify({name:el.value})}).then(()=>toast('已儲存')));\n  document.querySelectorAll('[data-pq]').forEach(el=>el.onchange=()=>api('/api/admin/periods/'+el.dataset.pq,{method:'PATCH',body:JSON.stringify({quota:el.value})}).then(()=>{toast('已儲存');reload();}));\n  document.querySelectorAll('[data-lock]').forEach(el=>el.onclick=()=>api('/api/admin/periods/'+el.dataset.lock,{method:'PATCH',body:JSON.stringify({status:'submitted'})}).then(reload));\n  document.querySelectorAll('[data-unlock]').forEach(el=>el.onclick=()=>api('/api/admin/periods/'+el.dataset.unlock,{method:'PATCH',body:JSON.stringify({status:'open'})}).then(reload));\n  document.querySelectorAll('[data-pdel]').forEach(el=>el.onclick=()=>armed(el,'確定刪除',()=>api('/api/admin/periods/'+el.dataset.pdel,{method:'DELETE'}).then(reload).catch(e=>toast(e.message,true))));\n  $('#np').onsubmit=async e=>{e.preventDefault();const f=Object.fromEntries(new FormData(e.target));await api('/api/admin/clients/'+C.client.id+'/periods',{method:'POST',body:JSON.stringify(f)});periodId=null;reload();};\n}\n\n/* report */\nfunction subReport(){\n  const R=C.client.report||{meta:{},findings:[],steps:[],sources:[]};R.meta=R.meta||{};R.findings=R.findings||[];R.steps=R.steps||[];R.sources=R.sources||[];\n  const F=(k,l)=>`<div class=\"fld\"><label>${l}</label><input class=\"in\" data-m=\"${k}\" value=\"${esc(R.meta[k])}\"></div>`;\n  $('#body').innerHTML=`<p class=\"small muted\">客戶頁的「關鍵字報告」分頁會顯示這些內容；「關鍵字與內容對應」會依關鍵字的「建議內容」欄位自動彙整。內文用反引號包住的字會顯示成關鍵字標籤。</p>\n  <div class=\"card\"><div class=\"grid2\">${F('title','報告標題')}${F('date','報告日期')}${F('market','市場')}${F('period','數據期間')}</div><div class=\"fld\" style=\"margin-top:10px\"><label>副標</label><textarea class=\"in\" data-m=\"subtitle\">${esc(R.meta.subtitle)}</textarea></div></div>\n  <h3 style=\"margin-top:20px\">重點結論</h3>${R.findings.map((f,i)=>`<div class=\"q-ed\"><div class=\"r\"><input class=\"in\" data-l=\"findings\" data-i=\"${i}\" data-k=\"k\" value=\"${esc(f.k)}\" placeholder=\"小標\"><input class=\"in\" data-l=\"findings\" data-i=\"${i}\" data-k=\"t\" value=\"${esc(f.t)}\" placeholder=\"標題\" style=\"grid-column:span 2\"><button class=\"btn sm danger\" data-ld=\"findings\" data-i=\"${i}\">刪除</button></div><textarea class=\"in\" data-l=\"findings\" data-i=\"${i}\" data-k=\"b\">${esc(f.b)}</textarea></div>`).join('')}<button class=\"btn sm\" data-la=\"findings\" style=\"margin-top:8px\">新增結論</button>\n  <h3 style=\"margin-top:20px\">執行與追蹤</h3>${R.steps.map((s,i)=>`<div class=\"q-ed\"><div class=\"r\"><input class=\"in\" data-l=\"steps\" data-i=\"${i}\" data-k=\"t\" value=\"${esc(s.t)}\"><input class=\"in\" data-l=\"steps\" data-i=\"${i}\" data-k=\"d\" value=\"${esc(s.d)}\" style=\"grid-column:span 2\"><button class=\"btn sm danger\" data-ld=\"steps\" data-i=\"${i}\">刪除</button></div></div>`).join('')}<button class=\"btn sm\" data-la=\"steps\" style=\"margin-top:8px\">新增步驟</button>\n  <h3 style=\"margin-top:20px\">資料來源說明</h3>${R.sources.map((s,i)=>`<div class=\"row\" style=\"margin-bottom:6px\"><input class=\"in grow\" data-l=\"sources\" data-i=\"${i}\" value=\"${esc(s)}\"><button class=\"btn sm danger\" data-ld=\"sources\" data-i=\"${i}\">刪除</button></div>`).join('')}<button class=\"btn sm\" data-la=\"sources\">新增說明</button>\n  <div class=\"stick\" style=\"bottom:0;top:auto;margin-top:20px;border-top:1px solid var(--line);border-bottom:0\"><button class=\"btn primary\" id=\"saveR\">儲存報告內容</button></div>`;\n  C.client.report=R;\n  document.querySelectorAll('[data-m]').forEach(el=>el.oninput=()=>R.meta[el.dataset.m]=el.value);\n  document.querySelectorAll('[data-l]').forEach(el=>el.oninput=()=>{const L=R[el.dataset.l];if(el.dataset.k)L[+el.dataset.i][el.dataset.k]=el.value;else L[+el.dataset.i]=el.value;});\n  document.querySelectorAll('[data-ld]').forEach(el=>el.onclick=()=>{R[el.dataset.ld].splice(+el.dataset.i,1);subReport();});\n  document.querySelectorAll('[data-la]').forEach(el=>el.onclick=()=>{const k=el.dataset.la;R[k].push(k==='sources'?'':k==='steps'?{t:'',d:''}:{k:'',t:'',b:''});subReport();});\n  $('#saveR').onclick=()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({report:R})}).then(()=>toast('已儲存')).catch(e=>toast(e.message,true));\n}\n\n/* interview */\nconst ST={prefill:'預填待確認',empty:'待填',done:'已確認'};\nfunction subIv(){\n  const I=C.client.interview||{meta:{},glossary:[],sections:[]};I.glossary=I.glossary||[];\n  const cnt={prefill:0,empty:0,done:0};I.sections.forEach(s=>s.items.forEach(it=>cnt[it.st]=(cnt[it.st]||0)+1));\n  $('#body').innerHTML=`<p class=\"small muted\">客戶可在客戶頁直接填寫答案；這裡可以編修題目、預填答案與狀態。目前：預填待確認 ${cnt.prefill}、待填 ${cnt.empty}、已確認 ${cnt.done}。</p>\n  <div class=\"card\"><div class=\"fld\"><label>說明文字</label><textarea class=\"in\" id=\"ivIntro\">${esc(I.meta?.intro)}</textarea></div></div>\n  <details class=\"card\" style=\"margin-top:12px\"><summary><b>名詞速讀</b>（${I.glossary.length}）</summary>${I.glossary.map((g,i)=>`<div class=\"row\" style=\"margin-top:6px\"><input class=\"in\" data-g=\"${i}\" data-k=\"t\" value=\"${esc(g.t)}\" style=\"max-width:220px\"><input class=\"in grow\" data-g=\"${i}\" data-k=\"d\" value=\"${esc(g.d)}\"><button class=\"btn sm danger\" data-gd=\"${i}\">刪除</button></div>`).join('')}<button class=\"btn sm\" id=\"gAdd\" style=\"margin-top:8px\">新增名詞</button></details>\n  ${I.sections.map((s,si)=>`<h3 style=\"margin-top:22px\">${esc(s.no)}、<input class=\"in\" data-sec=\"${si}\" value=\"${esc(s.title)}\" style=\"display:inline-block;width:auto;min-width:14em\"></h3>\n   ${s.items.map((it,ii)=>`<div class=\"q-ed\"><div class=\"r\"><input class=\"in\" data-q=\"${si}_${ii}\" data-k=\"q\" value=\"${esc(it.q)}\"><input class=\"in\" data-q=\"${si}_${ii}\" data-k=\"kw\" value=\"${esc(it.kw)}\" placeholder=\"對應關鍵字\"><select class=\"in\" data-q=\"${si}_${ii}\" data-k=\"st\">${Object.entries(ST).map(([k,l])=>`<option value=\"${k}\" ${it.st===k?'selected':''}>${l}</option>`).join('')}</select><button class=\"btn sm danger\" data-qd=\"${si}_${ii}\">刪除</button></div>\n    <input class=\"in\" data-q=\"${si}_${ii}\" data-k=\"hint\" value=\"${esc(it.hint)}\" placeholder=\"填寫提示\">\n    ${it.type==='table'?`<div class=\"tbl-scroll\"><table class=\"ed\"><thead><tr>${it.cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${it.rows.map((r,ri)=>`<tr>${r.map((v,ci)=>`<td><input class=\"in\" data-cell=\"${si}_${ii}_${ri}_${ci}\" value=\"${esc(v)}\"></td>`).join('')}</tr>`).join('')}</tbody></table></div><button class=\"btn sm\" data-ra=\"${si}_${ii}\" style=\"justify-self:start\">新增一列</button>`:`<textarea class=\"in\" data-q=\"${si}_${ii}\" data-k=\"a\">${esc(it.a)}</textarea>`}</div>`).join('')}\n   <button class=\"btn sm\" data-qa=\"${si}\" style=\"margin-top:8px\">新增題目</button>`).join('')}\n  <div class=\"stick\" style=\"bottom:0;top:auto;margin-top:20px;border-top:1px solid var(--line);border-bottom:0\"><button class=\"btn primary\" id=\"saveI\">儲存訪談表</button></div>`;\n  C.client.interview=I;\n  const P=s=>s.split('_').map(Number);\n  $('#ivIntro').oninput=e=>{I.meta=I.meta||{};I.meta.intro=e.target.value;};\n  document.querySelectorAll('[data-sec]').forEach(el=>el.oninput=()=>I.sections[+el.dataset.sec].title=el.value);\n  document.querySelectorAll('[data-q]').forEach(el=>el.oninput=el.onchange=()=>{const [si,ii]=P(el.dataset.q);I.sections[si].items[ii][el.dataset.k]=el.value;});\n  document.querySelectorAll('[data-cell]').forEach(el=>el.oninput=()=>{const [si,ii,ri,ci]=P(el.dataset.cell);I.sections[si].items[ii].rows[ri][ci]=el.value;});\n  document.querySelectorAll('[data-qd]').forEach(el=>el.onclick=()=>armed(el,'確定刪除',()=>{const [si,ii]=P(el.dataset.qd);I.sections[si].items.splice(ii,1);subIv();}));\n  document.querySelectorAll('[data-ra]').forEach(el=>el.onclick=()=>{const [si,ii]=P(el.dataset.ra);const it=I.sections[si].items[ii];it.rows.push(it.cols.map(()=>''));subIv();});\n  document.querySelectorAll('[data-qa]').forEach(el=>el.onclick=()=>{I.sections[+el.dataset.qa].items.push({type:'text',q:'新題目',a:'',st:'empty',src:'',hint:'',kw:''});subIv();});\n  document.querySelectorAll('[data-g]').forEach(el=>el.oninput=()=>I.glossary[+el.dataset.g][el.dataset.k]=el.value);\n  document.querySelectorAll('[data-gd]').forEach(el=>el.onclick=()=>{I.glossary.splice(+el.dataset.gd,1);subIv();});\n  $('#gAdd').onclick=()=>{I.glossary.push({t:'',d:''});subIv();};\n  $('#saveI').onclick=()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({interview:I})}).then(()=>toast('已儲存')).catch(e=>toast(e.message,true));\n}\n\n/* settings */\nfunction subSet(){\n  $('#body').innerHTML=`<div class=\"card\" style=\"max-width:640px\"><div class=\"fld\"><label>客戶名稱</label><div class=\"row\"><input class=\"in grow\" id=\"sName\" value=\"${esc(C.client.name)}\"><button class=\"btn sm\" id=\"sNameB\">儲存</button></div></div>\n  <div class=\"fld\" style=\"margin-top:14px\"><label>重設客戶 PIN 碼（4–6 位數字）</label><div class=\"row\"><input class=\"in grow\" id=\"sPin\" inputmode=\"numeric\" placeholder=\"輸入新的 PIN 碼\"><button class=\"btn sm\" id=\"sPinB\">更新 PIN</button></div><p class=\"small muted\">更新後，客戶需用新 PIN 重新登入。</p></div>\n  <div class=\"fld\" style=\"margin-top:14px\"><label>客戶連結</label><button class=\"btn sm danger\" id=\"sTok\">重新產生連結</button><p class=\"small muted\">舊連結會立即失效，適用於連結外流時。</p></div>\n  <div class=\"fld\" style=\"margin-top:14px\"><label>封存</label><button class=\"btn sm\" id=\"sArc\">${C.client.archived?'取消封存':'封存此客戶'}</button><p class=\"small muted\">封存後客戶連結無法開啟，資料保留。</p></div></div>`;\n  $('#sNameB').onclick=()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({name:$('#sName').value})}).then(()=>{toast('已儲存');reload();});\n  $('#sPinB').onclick=()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({pin:$('#sPin').value.trim()})}).then(()=>{toast('PIN 已更新');$('#sPin').value='';}).catch(e=>toast(e.message,true));\n  $('#sTok').onclick=e=>armed(e.target,'確定重新產生',()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({resetToken:true})}).then(()=>{toast('已產生新連結');reload();}));\n  $('#sArc').onclick=()=>api('/api/admin/clients/'+C.client.id,{method:'PATCH',body:JSON.stringify({archived:!C.client.archived})}).then(reload);\n}\nroute();\n</script></body></html>\n";
const CLIENT_HTML = "<!DOCTYPE html><html lang=\"zh-Hant\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\">\n<title>__TITLE__｜關鍵字選擇</title>\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\"><link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link href=\"https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=Noto+Sans+TC:wght@400;500;700;900&display=swap\" rel=\"stylesheet\">\n<style>:root{--navy:#071b2e;--navy2:#0d3453;--ink:#172433;--muted:#566676;--cyan:#28adc7;--orange:#f47a21;--green:#1f8a5b;--red:#c0392b;--pale:#f2f7fa;--line:#dce6ed;--bg:#fff;--card:#fff;--input:#fff;\n--font:\"IBM Plex Sans\",\"Noto Sans TC\",\"PingFang TC\",\"Microsoft JhengHei\",system-ui,sans-serif;color-scheme:light}\n@media (prefers-color-scheme:dark){:root{--ink:#e4edf4;--muted:#9fb1c1;--pale:#0f2335;--line:#223a50;--bg:#081624;--card:#0d2033;--navy:#050f1a;--navy2:#0a2a44;--input:#0a1a2a;color-scheme:dark}}\n*,*::before,*::after{box-sizing:border-box}\nhtml{scroll-padding-top:120px}\nbody{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:15.5px;line-height:1.65;-webkit-font-smoothing:antialiased}\na{color:inherit}\nbutton{font:inherit;cursor:pointer}\n:focus-visible{outline:2px solid var(--cyan);outline-offset:2px;border-radius:4px}\n.wrap{max-width:1180px;margin:0 auto;padding:0 20px}\n.narrow{max-width:460px}\nh1,h2,h3{line-height:1.3;margin:0}\nh1{font-size:clamp(24px,3vw,32px)} h2{font-size:22px} h3{font-size:17px}\n.muted{color:var(--muted)} .small{font-size:13px}\n.btn{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:7px 14px;border-radius:9px;font-size:14px;white-space:nowrap}\n.btn:hover{border-color:var(--cyan)}\n.btn.primary{background:var(--orange);border-color:var(--orange);color:#fff;font-weight:600}\n.btn.dark{background:var(--navy2);border-color:var(--navy2);color:#fff}\n.btn.danger{color:var(--red)} .btn.armed{background:var(--red);border-color:var(--red);color:#fff}\n.btn:disabled{opacity:.45;cursor:default}\n.btn.sm{padding:4px 10px;font-size:13px}\ninput.in,select.in,textarea.in{border:1px solid var(--line);background:var(--input);color:var(--ink);border-radius:8px;padding:7px 10px;font:inherit;font-size:14.5px;width:100%}\ntextarea.in{resize:vertical;min-height:4em;line-height:1.6}\ninput.in.n{text-align:right}\n.top{background:var(--navy);color:#e8f1f7}\n.top .wrap{display:flex;align-items:center;gap:16px;min-height:60px;flex-wrap:wrap;padding-top:8px;padding-bottom:8px}\n.brand{font-weight:700;letter-spacing:.02em}\n.brand small{display:block;font-size:12px;font-weight:500;color:#8fb3c9;letter-spacing:.04em}\n.tabs{display:flex;gap:4px;background:rgba(255,255,255,.08);padding:3px;border-radius:10px;margin-left:auto;flex-wrap:wrap}\n.tabs button{border:0;background:transparent;color:#b9ccda;padding:6px 12px;border-radius:8px;font-size:14px;font-weight:600}\n.tabs button[aria-selected=\"true\"]{background:#fff;color:var(--navy)}\n.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}\n.chip{display:inline-block;font-size:12.5px;font-weight:600;padding:1px 8px;border-radius:6px;white-space:nowrap;border:1px solid var(--line);color:var(--muted)}\n.chip.rec{background:var(--orange);border-color:var(--orange);color:#fff}\n.chip.past{background:var(--pale);color:var(--muted)}\n.chip.ok{background:var(--green);border-color:var(--green);color:#fff}\n.chip.open{background:color-mix(in srgb,var(--cyan) 20%,transparent);border-color:transparent;color:var(--ink)}\n.tbl-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}\ntable{border-collapse:collapse;width:100%;font-size:14.5px}\nth,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}\nth{font-size:12.5px;color:var(--muted);font-weight:600;background:var(--pale);white-space:nowrap;position:sticky;top:0}\ntr:last-child td{border-bottom:0}\ntd.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}\n.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--navy2);color:#fff;padding:10px 18px;border-radius:10px;font-size:14.5px;z-index:99;max-width:92vw;box-shadow:0 8px 24px rgba(0,0,0,.2)}\n.toast.err{background:var(--red)}\n.gate{min-height:100vh;display:grid;place-items:center;background:var(--navy);padding:20px}\n.gate .card{width:100%;max-width:380px}\n.gate h1{font-size:22px;margin-bottom:6px}\n.gate input{font-size:22px;letter-spacing:.3em;text-align:center}\n.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}\n.grow{flex:1}\n.empty{border:1px dashed var(--line);border-radius:12px;padding:18px;color:var(--muted);text-align:center}\n[hidden]{display:none!important}\n\n:root{--navy:#142c43;--navy2:#1d3d59;--teal:#14866f;--teal-soft:#e9f7f3;--blue-soft:#eaf1f7;--amber:#a35f0b;--amber-soft:#fff4df;--ink:#18242e;--muted:#5c6d79;--line:#d8e0e6;--bg:#f4f7f9;--card:#fff;--pale:#eef3f6;--shadow:0 16px 40px rgba(20,44,67,.09);--orange:#e07a1f}\n@media (prefers-color-scheme:dark){:root{--ink:#e4edf4;--muted:#9fb1c1;--line:#26405a;--bg:#0b1824;--card:#112436;--pale:#16304a;--teal-soft:#123a33;--blue-soft:#16304a;--amber-soft:#3a2a10}}\nbody{background:var(--bg)}\n.shell{max-width:1440px;margin:0 auto;padding:18px 24px 60px}\n.nav{display:flex;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:16px}\n.nav .brand{font-weight:800;color:var(--ink)} .nav .brand small{display:block;font-size:12px;color:var(--muted);font-weight:600;letter-spacing:.04em}\n.tabs2{display:flex;gap:4px;background:var(--card);border:1px solid var(--line);padding:4px;border-radius:12px;margin-left:auto}\n.tabs2 button{border:0;background:transparent;color:var(--muted);padding:7px 14px;border-radius:9px;font-weight:700;font-size:14px}\n.tabs2 button[aria-selected=\"true\"]{background:var(--navy);color:#fff}\n.hero{background:linear-gradient(135deg,var(--navy),var(--navy2));color:#fff;border-radius:22px;padding:28px 30px;box-shadow:var(--shadow);position:relative;overflow:hidden}\n.hero:after{content:\"\";position:absolute;right:-90px;top:-110px;width:310px;height:310px;border:54px solid rgba(85,194,170,.12);border-radius:50%}\n.eyebrow{margin:0 0 6px;color:#a7d9cd;font-size:.8rem;font-weight:800;letter-spacing:.13em;text-transform:uppercase}\n.hero h1{font-size:clamp(1.7rem,3vw,2.5rem);letter-spacing:-.02em;max-width:850px}\n.lede{max-width:860px;margin:12px 0 0;color:#dce8f0}\n.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:22px;max-width:900px;position:relative;z-index:1}\n.summary div{border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.07);border-radius:14px;padding:12px 15px}\n.summary strong{display:block;font-size:1.5rem;line-height:1.2}\n.summary span{display:block;color:#c8d7e2;font-size:.82rem;margin-top:4px}\n.guide{margin:18px 0;background:var(--card);border:1px solid var(--line);border-left:5px solid var(--teal);border-radius:14px;padding:15px 18px}\n.guide strong{display:block;color:var(--ink);margin-bottom:2px}\n.guide p{margin:0;color:var(--muted);font-size:14.5px}\n.workspace{display:grid;grid-template-columns:minmax(0,1fr) 330px;gap:20px;align-items:start}\n.toolbar{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:14px 16px;display:grid;grid-template-columns:minmax(200px,1.5fr) repeat(3,minmax(140px,.7fr));gap:12px;position:sticky;top:10px;z-index:5;box-shadow:0 10px 28px rgba(20,44,67,.07)}\n.toolbar label{display:block;font-weight:750;font-size:.8rem;color:var(--ink);margin-bottom:5px}\n.toolbar input,.toolbar select{width:100%;height:42px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--ink);padding:0 12px;font:inherit}\n.toolbar input:focus,.toolbar select:focus{outline:none;border-color:var(--teal);box-shadow:0 0 0 3px rgba(20,134,111,.13)}\n.resulthead{display:flex;justify-content:space-between;gap:16px;margin:14px 2px 10px;color:var(--muted);font-size:.9rem}\n.resulthead strong{color:var(--ink)}\n.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}\n.kcard{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;transition:border-color .18s,box-shadow .18s;position:relative;display:flex;flex-direction:column}\n.kcard:hover{border-color:#b9c8d1;box-shadow:0 10px 26px rgba(20,44,67,.08)}\n.kcard.on{border-color:var(--teal);box-shadow:0 0 0 2px rgba(20,134,111,.18)}\n.kcard.past{opacity:.62}\n.khead{display:flex;gap:10px;align-items:center;flex-wrap:wrap}\n.ck{appearance:none;width:26px;height:26px;border:2px solid #9aabb7;border-radius:7px;background:var(--card);cursor:pointer;display:grid;place-items:center;flex:none;margin:0}\n.ck:checked{background:var(--teal);border-color:var(--teal)}\n.ck:checked::after{content:\"\";width:7px;height:13px;border:solid #fff;border-width:0 3px 3px 0;transform:rotate(45deg) translate(-1px,-1px)}\n.ck:disabled{cursor:not-allowed;opacity:.5}\n.no{font-weight:800;font-size:12.5px;letter-spacing:.08em;color:var(--ink)}\n.tag{font-size:12px;font-weight:700;padding:2px 9px;border-radius:999px;background:var(--blue-soft);color:var(--navy2)}\n.tag.rec{background:var(--amber-soft);color:var(--amber)}\n.tag.past{background:var(--pale);color:var(--muted)}\n.tag.nodata{background:var(--pale);color:var(--muted);font-weight:600}\n@media (prefers-color-scheme:dark){.tag{color:#cfe0ee}}\n.ktitle{font-size:18px;font-weight:800;line-height:1.4;margin:12px 0 8px 36px}\n.kmain{margin-left:36px;font-size:14.5px}.kmain span{color:var(--muted);margin-right:10px}.kmain b{font-size:15.5px}\n.kdesc{margin:8px 0 0 36px;color:var(--muted);font-size:14.5px}\n.metrics{display:grid;grid-template-columns:repeat(3,1fr);border:1px solid var(--line);border-radius:12px;margin-top:14px;background:var(--bg);overflow:hidden}\n.metrics div{padding:9px 12px;border-left:1px solid var(--line)}.metrics div:first-child{border-left:0}\n.metrics span{display:block;font-size:12px;color:var(--muted)}.metrics b{font-size:16px;font-variant-numeric:tabular-nums}\n.more{margin-top:auto;padding-top:12px}\n.more details{border-top:1px solid var(--line);padding-top:10px}\n.more summary{cursor:pointer;color:var(--teal);font-weight:700;font-size:14px;list-style:none;display:flex;justify-content:space-between}\n.more summary::-webkit-details-marker{display:none}\n.more summary::after{content:\"+\";font-size:18px;line-height:1}.more details[open] summary::after{content:\"−\"}\n.more dl{margin:10px 0 0;display:grid;grid-template-columns:5.5em 1fr;gap:6px 10px;font-size:14px}.more dt{color:var(--muted)}.more dd{margin:0}\n.side{position:sticky;top:10px;background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 10px 28px rgba(20,44,67,.07)}\n.side h2{font-size:19px}.side .sub{color:var(--muted);font-size:14px;margin:6px 0 14px}\n.countbox{background:var(--navy);color:#fff;border-radius:14px;padding:14px 16px;display:flex;align-items:baseline;gap:6px}\n.countbox b{font-size:30px;line-height:1}.countbox .of{color:#b8c9d6}.countbox .st{margin-left:auto;color:#c8d7e2;font-size:14px}\n.pbar{height:8px;background:var(--pale);border-radius:4px;margin-top:12px;overflow:hidden;display:flex}\n.pbar i{display:block;height:100%}\n.remain{font-size:14px;color:var(--muted);margin-top:6px}\n.slist{list-style:none;margin:14px 0 0;padding:0;border-top:1px solid var(--line);max-height:38vh;overflow:auto}\n.slist li{display:flex;gap:10px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line);font-size:14.5px}\n.slist li .n{font-weight:800;font-size:12.5px;color:var(--muted);width:1.8em}\n.slist li .x{margin-left:auto;border:0;background:none;color:var(--muted);font-size:17px;padding:0 4px}\n.slist .empty2{color:var(--muted);font-size:14px;padding:10px 0}\n.sbtn{width:100%;margin-top:12px;height:46px;border-radius:12px;border:0;font-weight:800;font-size:15px}\n.sbtn.go{background:var(--teal);color:#fff}.sbtn.go.armed{background:#b3412f}.sbtn.go:disabled{background:#a9b6bf;cursor:default}\n.sbtn.ghost{background:var(--pale);color:var(--ink)}\n.hint2{font-size:12.5px;color:var(--muted);margin-top:12px}\n.donebox{background:var(--teal-soft);border:1px solid rgba(20,134,111,.35);color:var(--ink);border-radius:12px;padding:12px 14px;margin-top:12px;font-size:14px}\n.pastbox{margin-top:14px;font-size:14px}.pastbox summary{cursor:pointer;color:var(--muted)}\n.pastbox ul{margin:8px 0 0;padding-left:1.1em;color:var(--muted)}\n.mbar{display:none}\nsection.pane{padding:22px 0 60px}\n.plain{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:24px;margin-top:4px}\n.findings{display:grid;grid-template-columns:1fr 1fr;border-top:2px solid var(--ink);margin-top:14px}\n.finding{padding:18px 18px 18px 0;border-bottom:1px solid var(--line)}\n.finding:nth-child(even){padding-left:18px;border-left:1px solid var(--line)}\n.finding .k{color:var(--teal);font-weight:700;font-size:13.5px}\n.finding p{color:var(--muted);margin:6px 0 0}\ncode.kwc{font-family:inherit;background:var(--pale);padding:0 6px;border-radius:5px;color:var(--ink)}\n.steps{list-style:none;padding:0;margin:14px 0 0;display:grid;grid-template-columns:repeat(4,1fr);gap:18px;border-top:2px solid var(--ink);padding-top:14px}\n.steps b{display:block}\n.q{padding:18px 0;border-bottom:1px solid var(--line)}\n.q .qt{font-weight:700}\n.q .hint{color:var(--muted);font-size:13px;margin:2px 0 8px}\n.q .saved{font-size:12px;color:var(--teal);margin-left:8px}\n.sec{margin-top:30px}.sec h2 span{color:var(--teal);margin-right:8px}\n.q table input{border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:6px;padding:5px 7px;font:inherit;font-size:14px;width:100%;min-width:8em}\n.gloss{display:grid;grid-template-columns:repeat(3,1fr);gap:0 24px}.gloss div{padding:10px 0;border-bottom:1px solid var(--line)}.gloss b{display:block}\n@media (max-width:1100px){.workspace{grid-template-columns:1fr}.side{position:static}.toolbar{grid-template-columns:1fr 1fr}}\n@media (max-width:760px){.shell{padding:12px 12px 90px}.cards{grid-template-columns:1fr}.summary{grid-template-columns:1fr 1fr}.toolbar{position:static;grid-template-columns:1fr}.hero{padding:22px 20px}.ktitle,.kmain,.kdesc{margin-left:0}.findings,.steps,.gloss{grid-template-columns:1fr}.finding:nth-child(even){padding-left:0;border-left:0}\n .mbar{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:30;background:var(--navy);color:#fff;padding:10px 14px;gap:12px;align-items:center;box-shadow:0 -6px 20px rgba(0,0,0,.2)}\n .mbar b{font-size:20px}.mbar .grow{flex:1}.mbar button{border:0;background:var(--teal);color:#fff;font-weight:800;border-radius:10px;padding:9px 14px}}\n</style></head><body>\n<div id=\"gate\" class=\"gate\" hidden><form class=\"card\" id=\"pinForm\"><h1 id=\"gName\">關鍵字選擇</h1><p class=\"muted\">請輸入顧問提供的 PIN 碼</p><input class=\"in\" id=\"pin\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"6\" aria-label=\"PIN 碼\"><p id=\"pinErr\" class=\"small\" style=\"color:var(--red);min-height:1.5em\"></p><button class=\"btn primary\" style=\"width:100%\">進入</button></form></div>\n<div id=\"app\" hidden></div>\n<script>\nconst TOKEN=location.pathname.split('/').pop();\nconst API=p=>'/api/c/'+TOKEN+p;\nlet D=null, tab='select', filter='all', q='', onlySel=false;\nconst esc=s=>String(s==null?'':s).replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));\nconst fmt=(v,d=0)=>v==null?'':Number(v).toLocaleString('zh-TW',{minimumFractionDigits:d,maximumFractionDigits:d});\nfunction toast(m,err){const t=document.createElement('div');t.className='toast'+(err?' err':'');t.textContent=m;document.body.appendChild(t);setTimeout(()=>t.remove(),3000);}\nasync function api(p,opt={}){const r=await fetch(API(p),{credentials:'same-origin',headers:{'content-type':'application/json'},...opt});const j=await r.json().catch(()=>({}));if(!r.ok)throw Object.assign(new Error(j.error||'錯誤'),{status:r.status,body:j});return j;}\nasync function load(){\n  try{D=await api('/data');document.getElementById('gate').hidden=true;document.getElementById('app').hidden=false;document.title=D.name+'｜關鍵字選擇';render();}\n  catch(e){ if(e.status===401){document.getElementById('gate').hidden=false;document.getElementById('pin').focus();} else document.body.innerHTML='<div class=\"gate\"><div class=\"card\"><h1>無法載入</h1><p class=\"muted\">'+esc(e.message)+'</p></div></div>'; }\n}\ndocument.getElementById('pinForm').onsubmit=async e=>{e.preventDefault();const pin=document.getElementById('pin').value.trim();\n  try{await api('/pin',{method:'POST',body:JSON.stringify({pin})});load();}catch(err){document.getElementById('pinErr').textContent=err.message;}};\n\nfunction render(){\n  const hasReport=D.report&&((D.report.findings||[]).length||(D.report.steps||[]).length);\n  document.getElementById('app').innerHTML=`<div class=\"shell\">\n   <div class=\"nav\"><div class=\"brand\">${esc(D.name)}<small>MaKarma 瑪卡鎷行銷｜SEO 關鍵字</small></div>\n    <div class=\"tabs2\" role=\"tablist\">\n     <button role=\"tab\" data-t=\"select\" aria-selected=\"${tab==='select'}\">關鍵字選題</button>\n     ${hasReport?`<button role=\"tab\" data-t=\"report\" aria-selected=\"${tab==='report'}\">關鍵字報告</button>`:''}\n     ${D.interview?`<button role=\"tab\" data-t=\"iv\" aria-selected=\"${tab==='iv'}\">產業訪談表</button>`:''}\n    </div></div>\n   <main id=\"pane\"></main></div><div class=\"mbar\" id=\"mbar\"></div>`;\n  document.querySelectorAll('[data-t]').forEach(b=>b.onclick=()=>{tab=b.dataset.t;render();window.scrollTo(0,0);});\n  if(tab==='select')renderSelect(); else if(tab==='report')renderReport(); else renderIv();\n}\n\n/* ---------- selection ---------- */\nlet prio='all', show='all';\nfunction counts(){const P=D.period;const n=D.selected.length;return{n,quota:P?P.quota:0,rem:P?Math.max(0,P.quota-n):0};}\nfunction catName(id){const c=D.cats.find(x=>x.id===id);return c?c.name:'未分類';}\nfunction catsList(){const list=D.cats.filter(c=>D.kws.some(k=>k.c===c.id));if(D.kws.some(k=>!k.c||!D.cats.find(c=>c.id===k.c)))list.push({id:'',name:'未分類',note:''});return list;}\nfunction ordered(){const order=catsList().map(c=>c.id);return D.kws.slice().sort((a,b)=>(order.indexOf(a.c||'')-order.indexOf(b.c||''))||((!!D.past[a.id])-(!!D.past[b.id]))||(b.rec-a.rec)||((b.vol||0)-(a.vol||0)));}\nfunction renderSelect(){\n  const P=D.period; const pane=document.getElementById('pane');\n  if(!P){pane.innerHTML='<section class=\"pane\"><div class=\"plain\">目前沒有開放選題的期別，請聯繫您的顧問。</div></section>';return;}\n  const locked=P.status!=='open'; const cand=D.kws.filter(k=>!D.past[k.id]).length;\n  const withData=D.kws.filter(k=>!D.past[k.id]&&k.vol!=null).length;\n  pane.innerHTML=`\n  <section class=\"hero\"><p class=\"eyebrow\">SEO KEYWORD SELECTION｜${esc(P.name)}</p>\n   <h1>SEO 關鍵字候選題庫</h1>\n   <p class=\"lede\">這份頁面提供 ${cand} 組候選關鍵字與建議文章題目。請依品牌方向與業務優先順序，從中挑選 ${P.quota} 組作為本期的 SEO 文章題目。</p>\n   <div class=\"summary\">\n    <div><strong>${cand}</strong><span>候選關鍵字</span></div>\n    <div><strong>${P.quota}</strong><span>本期可選</span></div>\n    ${D.contract!=null?`<div><strong>${D.contract}</strong><span>合約總篇數</span></div><div><strong>${D.pastCount}</strong><span>過往已選</span></div>`:`<div><strong>${withData}</strong><span>有 Google Ads 數據</span></div>`}\n   </div></section>\n  <div class=\"guide\"><strong>如何閱讀數據</strong><p>月搜尋量與頁首出價上限來自 Google Ads 關鍵字規劃工具（台灣）；頁首出價越高，代表越多廣告主願意為這個字付費。「優先推薦」為顧問建議先做的題目。勾選會自動儲存，選好後按「送出確認」。</p></div>\n  <div class=\"workspace\">\n   <div>\n    <div class=\"toolbar\">\n     <div><label for=\"q\">搜尋題目或關鍵字</label><input id=\"q\" type=\"search\" placeholder=\"輸入關鍵字\" value=\"${esc(q)}\"></div>\n     <div><label for=\"fc\">分類</label><select id=\"fc\"><option value=\"all\">全部分類</option>${catsList().map(c=>`<option value=\"${c.id}\" ${filter===c.id?'selected':''}>${esc(c.name)}</option>`).join('')}</select></div>\n     <div><label for=\"fp\">策略優先度</label><select id=\"fp\"><option value=\"all\">全部</option><option value=\"rec\" ${prio==='rec'?'selected':''}>優先推薦</option></select></div>\n     <div><label for=\"fs\">顯示</label><select id=\"fs\"><option value=\"all\">全部候選</option><option value=\"sel\" ${show==='sel'?'selected':''}>只看已選</option><option value=\"unsel\" ${show==='unsel'?'selected':''}>只看未選</option><option value=\"past\" ${show==='past'?'selected':''}>過往已選</option></select></div>\n    </div>\n    <div class=\"resulthead\"><span id=\"rc\"></span><span>展開卡片可查看可導向與備註</span></div>\n    <div class=\"cards\" id=\"cards\"></div>\n   </div>\n   <aside class=\"side\" id=\"side\"></aside>\n  </div>`;\n  document.getElementById('q').oninput=e=>{q=e.target.value;renderCards();};\n  document.getElementById('fc').onchange=e=>{filter=e.target.value;renderCards();};\n  document.getElementById('fp').onchange=e=>{prio=e.target.value;renderCards();};\n  document.getElementById('fs').onchange=e=>{show=e.target.value;renderCards();};\n  renderCards(); renderSide();\n}\nfunction visible(){const qq=q.trim().toLowerCase();\n  return ordered().filter(k=>(filter==='all'||(k.c||'')===filter)&&(prio==='all'||k.rec)\n   &&(show==='all'?true:show==='sel'?D.selected.includes(k.id):show==='unsel'?(!D.selected.includes(k.id)&&!D.past[k.id]):!!D.past[k.id])\n   &&(!qq||[k.kw,k.content,k.intent,k.note,k.path].join(' ').toLowerCase().includes(qq)));}\nfunction renderCards(){\n  const all=ordered(); const idx=new Map(all.map((k,i)=>[k.id,i+1])); const vs=visible(); const c=counts(); const locked=D.period.status!=='open';\n  document.getElementById('rc').innerHTML=`顯示 <strong>${vs.length}</strong> / ${all.length} 組`;\n  document.getElementById('cards').innerHTML=vs.map(k=>{const on=D.selected.includes(k.id),past=D.past[k.id];const dis=past||locked||(!on&&c.rem===0);\n    const title=k.content||k.kw;\n    return `<article class=\"kcard ${on?'on':''} ${past?'past':''}\"><div class=\"khead\">\n     <input type=\"checkbox\" class=\"ck\" data-id=\"${k.id}\" ${on||past?'checked':''} ${dis?'disabled':''} aria-label=\"選擇 ${esc(k.kw)}\" title=\"${past?'已在'+esc(past)+'選過':(!on&&c.rem===0&&!locked?'已達本期可選數量':'')}\">\n     <span class=\"no\">NO. ${String(idx.get(k.id)).padStart(2,'0')}</span><span class=\"tag\">${esc(catName(k.c))}</span>\n     ${k.rec?'<span class=\"tag rec\">優先推薦</span>':''}${past?`<span class=\"tag past\">已選過｜${esc(past)}</span>`:''}${k.vol==null?'<span class=\"tag nodata\">探索型／待驗證</span>':''}</div>\n     <div class=\"ktitle\">${esc(title)}</div>\n     ${k.content?`<div class=\"kmain\"><span>主關鍵字</span><b>${esc(k.kw)}</b></div>`:''}\n     ${k.intent?`<p class=\"kdesc\">${esc(k.intent)}</p>`:''}\n     <div class=\"metrics\"><div><span>平均月搜尋量</span><b>${k.vol!=null?fmt(k.vol):'—'}</b></div><div><span>廣告競爭程度</span><b>${esc(k.comp)||'—'}</b></div><div><span>頁首出價上限</span><b>${k.hi!=null?'NT$'+fmt(k.hi,2):'—'}</b></div></div>\n     ${(k.path||k.note)?`<div class=\"more\"><details><summary>查看可導向與備註</summary><dl>${k.path?`<dt>可導向</dt><dd>${esc(k.path)}</dd>`:''}${k.note?`<dt>備註</dt><dd>${esc(k.note)}</dd>`:''}</dl></details></div>`:''}\n    </article>`;}).join('')||'<div class=\"plain\" style=\"grid-column:1/-1\">沒有符合條件的關鍵字</div>';\n  document.querySelectorAll('#cards .ck').forEach(cb=>cb.onchange=()=>toggle(cb.dataset.id,cb.checked,cb));\n}\nfunction renderSide(){\n  const P=D.period,c=counts(),locked=P.status!=='open';\n  const sel=ordered().filter(k=>D.selected.includes(k.id)); const past=ordered().filter(k=>D.past[k.id]);\n  const T=D.contract;\n  const st=locked?'已送出':c.n===0?'尚未開始':c.rem===0?'已選滿':'選擇中';\n  document.getElementById('side').innerHTML=`<h2>本期已選</h2><p class=\"sub\">最多選擇 ${P.quota} 組${T!=null?`（合約共 ${T} 篇，過往已選 ${D.pastCount} 篇）`:''}。</p>\n   <div class=\"countbox\"><b>${c.n}</b><span class=\"of\">/ ${P.quota}</span><span class=\"st\">${st}</span></div>\n   <div class=\"pbar\"><i style=\"width:${P.quota?Math.min(100,c.n/P.quota*100):0}%;background:var(--teal)\"></i></div>\n   <div class=\"remain\">${locked?'這一期已送出，如需調整請聯繫顧問。':'還可選擇 '+c.rem+' 組'}</div>\n   <ul class=\"slist\">${sel.length?sel.map((k,i)=>`<li><span class=\"n\">${String(i+1).padStart(2,'0')}</span><span>${esc(k.kw)}</span>${locked?'':`<button class=\"x\" data-rm=\"${k.id}\" aria-label=\"移除 ${esc(k.kw)}\">×</button>`}</li>`).join(''):'<li class=\"empty2\">尚未選擇題目</li>'}</ul>\n   ${locked?`<div class=\"donebox\">已於 ${P.submitted_at?new Date(P.submitted_at).toLocaleDateString('zh-TW'):''} 送出，顧問已收到通知。</div>`:`<button class=\"sbtn go\" id=\"submit\" ${c.n?'':'disabled'}>送出確認</button>`}\n   <button class=\"sbtn ghost\" id=\"csv\" ${c.n?'':'disabled'}>下載已選清單 CSV</button>\n   ${past.length?`<details class=\"pastbox\"><summary>過往已選 ${past.length} 組（不需要再選）</summary><ul>${past.map(k=>`<li>${esc(k.kw)}｜${esc(D.past[k.id])}</li>`).join('')}</ul></details>`:''}\n   <p class=\"hint2\">勾選會即時儲存；送出後會通知顧問並鎖定本期選題。</p>`;\n  document.querySelectorAll('[data-rm]').forEach(b=>b.onclick=()=>toggle(b.dataset.rm,false));\n  const sb=document.getElementById('submit'); if(sb)sb.onclick=()=>armedSubmit(sb);\n  document.getElementById('csv').onclick=downloadCsv;\n  const mb=document.getElementById('mbar'); if(mb) mb.innerHTML=`<div><b>${c.n}</b> / ${P.quota}<div class=\"small\" style=\"color:#c8d7e2\">${st}</div></div><div class=\"grow\"></div>${locked?'':`<button id=\"msubmit\" ${c.n?'':'disabled'}>送出確認</button>`}`;\n  const ms=document.getElementById('msubmit'); if(ms) ms.onclick=()=>armedSubmit(ms);\n}\nasync function toggle(id,on,cb){\n  try{await api('/select',{method:'POST',body:JSON.stringify({keyword_id:id,selected:on})});\n    if(on){if(!D.selected.includes(id))D.selected.push(id);}else D.selected=D.selected.filter(x=>x!==id);\n    renderCards();renderSide();}\n  catch(e){if(cb)cb.checked=!on;toast(e.message,true);}}\nfunction armedSubmit(b){const c=counts();\n  if(b.dataset.armed!=='1'){if(!c.n){toast('尚未選擇任何關鍵字',true);return;}b.dataset.armed='1';b.textContent=`確定送出 ${c.n} 組？再按一次`;b.classList.add('armed');setTimeout(()=>{if(b.isConnected){b.dataset.armed='';b.textContent='送出確認';b.classList.remove('armed');}},4000);return;}\n  b.disabled=true;api('/submit',{method:'POST'}).then(()=>{toast('已送出，顧問會收到通知');load();}).catch(e=>{b.disabled=false;toast(e.message,true);});}\nfunction downloadCsv(){const rows=[['編號','分類','主關鍵字','建議文章','月搜尋量','頁首出價上限','可導向']];\n  ordered().filter(k=>D.selected.includes(k.id)).forEach((k,i)=>rows.push([i+1,catName(k.c),k.kw,k.content||'',k.vol??'',k.hi??'',k.path||'']));\n  const csv='\\uFEFF'+rows.map(r=>r.map(x=>'\"'+String(x).replace(/\"/g,'\"\"')+'\"').join(',')).join('\\r\\n');\n  const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));a.download=D.name+'_'+D.period.name+'_選題.csv';a.click();}\n\n/* ---------- report ---------- */\nfunction rich(s){return esc(s).replace(/`([^`]+)`/g,'<code class=\"kwc\">$1</code>');}\nfunction renderReport(){const R=D.report||{};const m=R.meta||{};\n  const groups={};D.kws.filter(k=>k.content).forEach(k=>(groups[k.content]=groups[k.content]||[]).push(k));\n  document.getElementById('pane').innerHTML=`<div><section class=\"pane plain\">\n   <h1>${esc(m.title||'關鍵字策略報告')}</h1>${m.subtitle?`<p class=\"muted\" style=\"max-width:44em\">${esc(m.subtitle)}</p>`:''}\n   <p class=\"small muted\">${[m.date&&'報告日期 '+m.date,m.market&&'市場 '+m.market,m.period&&'數據期間 '+m.period].filter(Boolean).map(esc).join('｜')}</p>\n   ${(R.findings||[]).length?`<h2 style=\"margin-top:28px\">重點結論</h2><div class=\"findings\">${R.findings.map(f=>`<div class=\"finding\"><div class=\"k\">${esc(f.k)}</div><h3>${esc(f.t)}</h3><p>${rich(f.b)}</p></div>`).join('')}</div>`:''}\n   ${Object.keys(groups).length?`<h2 style=\"margin-top:32px\">關鍵字與內容對應</h2><div class=\"tbl-scroll\" style=\"margin-top:12px\"><table><thead><tr><th>建議內容</th><th>對應關鍵字</th><th class=\"num\">月搜尋量合計</th></tr></thead><tbody>${Object.entries(groups).map(([k,ks])=>`<tr><td><b>${esc(k)}</b></td><td>${ks.map(x=>esc(x.kw)).join('、')}</td><td class=\"num\">${fmt(ks.reduce((a,x)=>a+(x.vol||0),0))}</td></tr>`).join('')}</tbody></table></div>`:''}\n   ${(R.steps||[]).length?`<h2 style=\"margin-top:32px\">執行與追蹤</h2><ol class=\"steps\">${R.steps.map(s=>`<li><b>${esc(s.t)}</b><span class=\"muted\">${esc(s.d)}</span></li>`).join('')}</ol>`:''}\n   ${(R.sources||[]).length?`<h3 style=\"margin-top:32px\">資料來源與判讀說明</h3><ul class=\"muted small\">${R.sources.map(s=>`<li>${esc(s)}</li>`).join('')}</ul>`:''}\n  </section></div>`;}\n\n/* ---------- interview ---------- */\nconst timers={};\nfunction renderIv(){const I=D.interview;\n  document.getElementById('pane').innerHTML=`<div><section class=\"pane plain\">\n   <h1>${esc(I.meta?.title||'產業深度訪談表')}</h1><p class=\"muted\">${esc(I.meta?.intro||'')}</p><p class=\"small muted\">填寫內容會自動儲存，可以分次完成。</p>\n   ${(I.glossary||[]).length?`<h2 style=\"margin-top:24px\">名詞速讀</h2><div class=\"gloss\">${I.glossary.map(g=>`<div><b>${esc(g.t)}</b><span class=\"muted small\">${esc(g.d)}</span></div>`).join('')}</div>`:''}\n   ${(I.sections||[]).map((s,si)=>`<div class=\"sec\"><h2><span>${esc(s.no)}</span>${esc(s.title)}</h2>${s.intro?`<p class=\"muted small\">${esc(s.intro)}</p>`:''}\n     ${s.items.map((it,ii)=>`<div class=\"q\"><div class=\"qt\">${esc(it.q)}<span class=\"saved\" id=\"sv_${si}_${ii}\"></span></div>${it.hint?`<div class=\"hint\">${esc(it.hint)}${it.st==='prefill'?'　▸ 已預填，請確認或修正':''}</div>`:(it.st==='prefill'?'<div class=\"hint\">已預填，請確認或修正</div>':'')}\n      ${it.type==='table'?`<div class=\"tbl-scroll\"><table><thead><tr>${it.cols.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${it.rows.map((r,ri)=>`<tr>${r.map((v,ci)=>`<td><input data-si=\"${si}\" data-ii=\"${ii}\" data-ri=\"${ri}\" data-ci=\"${ci}\" value=\"${esc(v)}\" aria-label=\"${esc(it.cols[ci])}\"></td>`).join('')}</tr>`).join('')}</tbody></table></div><button class=\"btn sm\" style=\"margin-top:6px\" data-addrow=\"${si}_${ii}\">新增一列</button>`\n      :`<textarea class=\"in\" rows=\"3\" data-si=\"${si}\" data-ii=\"${ii}\" aria-label=\"回答\">${esc(it.a)}</textarea>`}</div>`).join('')}</div>`).join('')}\n  </section></div>`;\n  document.querySelectorAll('#pane textarea[data-si],#pane input[data-si]').forEach(el=>el.oninput=()=>{const it=D.interview.sections[el.dataset.si].items[el.dataset.ii];\n    if(it.type==='table')it.rows[el.dataset.ri][el.dataset.ci]=el.value;else it.a=el.value;schedule(+el.dataset.si,+el.dataset.ii);});\n  document.querySelectorAll('[data-addrow]').forEach(b=>b.onclick=()=>{const [si,ii]=b.dataset.addrow.split('_').map(Number);const it=D.interview.sections[si].items[ii];it.rows.push(it.cols.map(()=>''));schedule(si,ii);renderIv();});\n}\nfunction schedule(si,ii){const k=si+'_'+ii;clearTimeout(timers[k]);const s=document.getElementById('sv_'+k);if(s)s.textContent='儲存中…';\n  timers[k]=setTimeout(async()=>{const it=D.interview.sections[si].items[ii];\n    try{await api('/interview',{method:'PUT',body:JSON.stringify({items:[{si,ii,a:it.a,rows:it.rows}]})});const s2=document.getElementById('sv_'+k);if(s2)s2.textContent='已儲存';}\n    catch(e){toast('儲存失敗：'+e.message,true);}},800);}\nload();\n</script></body></html>\n";
function page(title: string, body: string) { return `<!DOCTYPE html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>:root{--navy:#071b2e;--navy2:#0d3453;--ink:#172433;--muted:#566676;--cyan:#28adc7;--orange:#f47a21;--green:#1f8a5b;--red:#c0392b;--pale:#f2f7fa;--line:#dce6ed;--bg:#fff;--card:#fff;--input:#fff;
--font:"IBM Plex Sans","Noto Sans TC","PingFang TC","Microsoft JhengHei",system-ui,sans-serif;color-scheme:light}
@media (prefers-color-scheme:dark){:root{--ink:#e4edf4;--muted:#9fb1c1;--pale:#0f2335;--line:#223a50;--bg:#081624;--card:#0d2033;--navy:#050f1a;--navy2:#0a2a44;--input:#0a1a2a;color-scheme:dark}}
*,*::before,*::after{box-sizing:border-box}
html{scroll-padding-top:120px}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:15.5px;line-height:1.65;-webkit-font-smoothing:antialiased}
a{color:inherit}
button{font:inherit;cursor:pointer}
:focus-visible{outline:2px solid var(--cyan);outline-offset:2px;border-radius:4px}
.wrap{max-width:1180px;margin:0 auto;padding:0 20px}
.narrow{max-width:460px}
h1,h2,h3{line-height:1.3;margin:0}
h1{font-size:clamp(24px,3vw,32px)} h2{font-size:22px} h3{font-size:17px}
.muted{color:var(--muted)} .small{font-size:13px}
.btn{border:1px solid var(--line);background:var(--card);color:var(--ink);padding:7px 14px;border-radius:9px;font-size:14px;white-space:nowrap}
.btn:hover{border-color:var(--cyan)}
.btn.primary{background:var(--orange);border-color:var(--orange);color:#fff;font-weight:600}
.btn.dark{background:var(--navy2);border-color:var(--navy2);color:#fff}
.btn.danger{color:var(--red)} .btn.armed{background:var(--red);border-color:var(--red);color:#fff}
.btn:disabled{opacity:.45;cursor:default}
.btn.sm{padding:4px 10px;font-size:13px}
input.in,select.in,textarea.in{border:1px solid var(--line);background:var(--input);color:var(--ink);border-radius:8px;padding:7px 10px;font:inherit;font-size:14.5px;width:100%}
textarea.in{resize:vertical;min-height:4em;line-height:1.6}
input.in.n{text-align:right}
.top{background:var(--navy);color:#e8f1f7}
.top .wrap{display:flex;align-items:center;gap:16px;min-height:60px;flex-wrap:wrap;padding-top:8px;padding-bottom:8px}
.brand{font-weight:700;letter-spacing:.02em}
.brand small{display:block;font-size:12px;font-weight:500;color:#8fb3c9;letter-spacing:.04em}
.tabs{display:flex;gap:4px;background:rgba(255,255,255,.08);padding:3px;border-radius:10px;margin-left:auto;flex-wrap:wrap}
.tabs button{border:0;background:transparent;color:#b9ccda;padding:6px 12px;border-radius:8px;font-size:14px;font-weight:600}
.tabs button[aria-selected="true"]{background:#fff;color:var(--navy)}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px}
.chip{display:inline-block;font-size:12.5px;font-weight:600;padding:1px 8px;border-radius:6px;white-space:nowrap;border:1px solid var(--line);color:var(--muted)}
.chip.rec{background:var(--orange);border-color:var(--orange);color:#fff}
.chip.past{background:var(--pale);color:var(--muted)}
.chip.ok{background:var(--green);border-color:var(--green);color:#fff}
.chip.open{background:color-mix(in srgb,var(--cyan) 20%,transparent);border-color:transparent;color:var(--ink)}
.tbl-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:14.5px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12.5px;color:var(--muted);font-weight:600;background:var(--pale);white-space:nowrap;position:sticky;top:0}
tr:last-child td{border-bottom:0}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%);background:var(--navy2);color:#fff;padding:10px 18px;border-radius:10px;font-size:14.5px;z-index:99;max-width:92vw;box-shadow:0 8px 24px rgba(0,0,0,.2)}
.toast.err{background:var(--red)}
.gate{min-height:100vh;display:grid;place-items:center;background:var(--navy);padding:20px}
.gate .card{width:100%;max-width:380px}
.gate h1{font-size:22px;margin-bottom:6px}
.gate input{font-size:22px;letter-spacing:.3em;text-align:center}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.grow{flex:1}
.empty{border:1px dashed var(--line);border-radius:12px;padding:18px;color:var(--muted);text-align:center}
[hidden]{display:none!important}
</style></head><body>${body}</body></html>`; }

export default { port: Number(Bun.env.PORT) || 3000, fetch: app.fetch };
