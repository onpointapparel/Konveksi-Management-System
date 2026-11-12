import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (body: unknown, status=200) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    const { action, role, username, password } = await req.json();
    if (action !== "login") return json({ error: "Action tidak valid." }, 400);
    const normalized = String(username || "").trim().toLowerCase();
    const normalizedRole = String(role || "").toLowerCase();
    if (!/^[a-z0-9._-]{3,30}$/.test(normalized)) return json({ error: "Username atau password salah." }, 401);
    if (!["owner","cs","produksi"].includes(normalizedRole) || !password) return json({ error: "Username atau password salah." }, 401);

    const url = Deno.env.get("SUPABASE_URL")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
    const admin = createClient(url, service, { auth: { persistSession: false } });
    const { data: profile, error: profileError } = await admin.from("users")
      .select("auth_user_id,role,active")
      .eq("username", normalized).maybeSingle();
    if (profileError || !profile || !profile.active || String(profile.role).toLowerCase() !== normalizedRole)
      return json({ error: "Username, role, atau password tidak sesuai." }, 401);

    const { data: authData, error: authError } = await admin.auth.admin.getUserById(profile.auth_user_id);
    if (authError || !authData.user?.email) return json({ error: "Akun Auth tidak ditemukan." }, 401);

    const response = await fetch(`${url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "apikey": anon },
      body: JSON.stringify({ email: authData.user.email, password })
    });
    const session = await response.json();
    if (!response.ok) return json({ error: "Username, role, atau password tidak sesuai." }, 401);
    return json({ ok: true, session: {
      access_token: session.access_token,
      refresh_token: session.refresh_token
    }});
  } catch (e) { return json({ error: e?.message || "Login gagal." }, 400); }
});
