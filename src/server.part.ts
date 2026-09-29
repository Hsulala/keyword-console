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
