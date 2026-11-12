import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (body: unknown, status=200) => new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    const authHeader = req.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    if (!token) return json({ error: "Sesi Owner diperlukan." }, 401);
    const url = Deno.env.get("SUPABASE_URL")!;
    const service = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
    const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
    const admin = createClient(url, service, { auth: { persistSession: false } });
    const caller = createClient(url, anon, { global: { headers: { Authorization: `Bearer ${token}` } }, auth: { persistSession: false } });
    const { data: userData, error: userError } = await caller.auth.getUser();
    if (userError || !userData.user) return json({ error: "Sesi tidak valid." }, 401);
    const { data: owner } = await admin.from("users").select("role,active")
      .eq("auth_user_id", userData.user.id).maybeSingle();
    if (!owner || !owner.active || owner.role !== "owner") return json({ error: "Hanya Owner yang dapat mengelola pengguna." }, 403);

    const body = await req.json();
    if (body.action === "list") {
      const { data, error } = await admin.from("users")
        .select("user_id,name,username,role,active,created_at")
        .order("created_at", { ascending: true });
      if (error) throw error;
      return json({ ok: true, users: data || [] });
    }

    if (body.action === "create") {
      const name = String(body.name || "").trim();
      const username = String(body.username || "").trim().toLowerCase();
      const role = String(body.role || "").toLowerCase();
      const password = String(body.password || "");
      if (!name || name.length > 100) return json({ error: "Nama wajib diisi (maksimal 100 karakter)." }, 400);
      if (!/^[a-z0-9._-]{3,30}$/.test(username)) return json({ error: "Username 3-30 karakter: huruf kecil, angka, titik, garis bawah, atau strip." }, 400);
      if (!["cs","produksi"].includes(role)) return json({ error: "Owner hanya dapat membuat role CS/Admin atau Produksi." }, 400);
      if (password.length < 8) return json({ error: "Password minimal 8 karakter." }, 400);
      const { data: existing } = await admin.from("users").select("user_id").ilike("username", username).maybeSingle();
      if (existing) return json({ error: "Username sudah digunakan." }, 409);

      // Email internal unik, tidak pernah ditampilkan kepada pengguna.
      const internalEmail = `${username}.${crypto.randomUUID().slice(0,8)}@login.konveksi-management.invalid`;
      const { data: created, error: createError } = await admin.auth.admin.createUser({
        email: internalEmail, password, email_confirm: true,
        user_metadata: { username, display_name: name }
      });
      if (createError || !created.user) throw createError || new Error("Gagal membuat akun Auth.");
      const { error: insertError } = await admin.from("users").insert({
        auth_user_id: created.user.id, username, name, role, active: true
      });
      if (insertError) {
        await admin.auth.admin.deleteUser(created.user.id);
        throw insertError;
      }
      return json({ ok: true });
    }

    if (body.action === "set-active") {
      const id = String(body.user_id || "");
      const active = Boolean(body.active);
      const { data: target, error: targetError } = await admin.from("users")
        .select("user_id,role,auth_user_id").eq("user_id", id).maybeSingle();
      if (targetError || !target) return json({ error: "Pengguna tidak ditemukan." }, 404);
      if (target.role === "owner" || target.auth_user_id === userData.user.id)
        return json({ error: "Akun Owner utama tidak dapat dinonaktifkan dari menu ini." }, 403);
      const { error } = await admin.from("users").update({ active, updated_at: new Date().toISOString() }).eq("user_id", id);
      if (error) throw error;
      return json({ ok: true });
    }
    return json({ error: "Action tidak dikenal." }, 400);
  } catch (e) { return json({ error: e?.message || "Operasi gagal." }, 400); }
});
