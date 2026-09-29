// Bootstrap loader: the application code is stored in Postgres and loaded at runtime.
// Updates are pushed to /__deploy with the DEPLOY_TOKEN header.
import { sql } from "bun";
import { Hono } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
void Hono; void getCookie; void setCookie; void deleteCookie;

const TOKEN = Bun.env.DEPLOY_TOKEN || "";
await sql`CREATE TABLE IF NOT EXISTS app_code (id int PRIMARY KEY, code text NOT NULL, updated_at timestamptz DEFAULT now())`;
let app: any = null;
let version = 0;
async function load(code: string) {
  version++;
  const file = `${import.meta.dir}/app_${Date.now()}_${version}.tsx`;
  await Bun.write(file, code);
  const mod = await import(file);
  app = mod.default;
}
try {
  const r = await sql`SELECT code FROM app_code WHERE id=1`;
  if (r.length) await load(r[0].code);
} catch (e) { console.error("load failed", e); }

function eq(a: string, b: string) { if (a.length !== b.length) return false; let x = 0; for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i); return x === 0; }

export default {
  port: Number(Bun.env.PORT) || 3000,
  async fetch(req: Request, server: any) {
    const url = new URL(req.url);
    if (url.pathname === "/__deploy" && req.method === "POST") {
      if (!TOKEN || !eq(req.headers.get("x-deploy-token") || "", TOKEN)) return new Response("forbidden", { status: 403 });
      const code = await req.text();
      try { await load(code); } catch (e: any) { return new Response("load error: " + (e?.message || e), { status: 500 }); }
      await sql`INSERT INTO app_code (id, code) VALUES (1, ${code}) ON CONFLICT (id) DO UPDATE SET code=EXCLUDED.code, updated_at=now()`;
      return new Response("deployed v" + version);
    }
    if (!app) return new Response("尚未部署", { status: 503 });
    return app.fetch(req, server);
  },
};
