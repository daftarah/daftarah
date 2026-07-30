/**
 * دفترة — سيرفر أكواد التفعيل
 * Cloudflare Worker + KV
 *
 * الإعداد:
 *   1) أنشئ KV namespace واربطه بالاسم:  LIC
 *   2) أضف متغير سري:                    ADMIN_KEY  (اختر قيمة طويلة وعشوائية)
 *
 * الواجهات:
 *   ?a=check&code=1234                          ← عام: يفعّل الرمز أول مرة ويعيد تاريخ الانتهاء
 *   ?a=issue&key=ADMIN_KEY&n=10&days=365&len=4  ← إداري: توليد أكواد
 *   ?a=list&key=ADMIN_KEY                       ← إداري: قائمة الأكواد وحالاتها
 *   ?a=revoke&key=ADMIN_KEY&code=1234           ← إداري: إيقاف رمز
 *   ?a=extend&key=ADMIN_KEY&code=1234&days=365  ← إداري: تجديد رمز
 */

const DAY = 86400000;
const MAX_LIST = 300;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const q = url.searchParams;
    const action = q.get("a") || "";

    const headers = {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,OPTIONS",
      "access-control-allow-headers": "*",
      "cache-control": "no-store",
    };
    const json = (body, status = 200) =>
      new Response(JSON.stringify(body), { status, headers });

    if (request.method === "OPTIONS") return new Response(null, { headers });
    if (!env.LIC) return json({ error: "KV binding LIC is missing" }, 500);

    const isAdmin = () => {
      const k = q.get("key") || "";
      return env.ADMIN_KEY && k.length > 0 && k === env.ADMIN_KEY;
    };
    const read = async (code) => {
      const raw = await env.LIC.get("c:" + code);
      return raw ? JSON.parse(raw) : null;
    };
    const write = (code, rec) => env.LIC.put("c:" + code, JSON.stringify(rec));

    // ── عام: تحقق من الرمز، ويبدأ العد من أول استخدام ──
    if (action === "check") {
      const code = (q.get("code") || "").trim();
      if (!code) return json({ ok: false, msg: "أدخل الرمز." });

      const rec = await read(code);
      if (!rec) return json({ ok: false, msg: "رمز غير صحيح." });
      if (rec.revoked) return json({ ok: false, msg: "هذا الرمز موقوف." });

      if (!rec.activated) {
        rec.activated = Date.now();
        rec.uses = 1;
        await write(code, rec);
      } else {
        rec.uses = (rec.uses || 1) + 1;
        rec.lastSeen = Date.now();
        await write(code, rec);
      }

      const until = rec.activated + (rec.days || 365) * DAY;
      return json(
        Date.now() < until
          ? { ok: true, until }
          : { ok: false, msg: "انتهت صلاحية هذا الرمز." }
      );
    }

    // ── إداري: توليد أكواد ──
    if (action === "issue") {
      if (!isAdmin()) return json({ error: "unauthorized" }, 401);

      const n = Math.min(Math.max(parseInt(q.get("n") || "1", 10), 1), 500);
      const days = Math.min(Math.max(parseInt(q.get("days") || "365", 10), 1), 3650);
      const lenRaw = parseInt(q.get("len") || "4", 10);
      const len = [4, 6, 8].includes(lenRaw) ? lenRaw : 4;
      const space = Math.pow(10, len);
      if (n > space * 0.2)
        return json({ error: "too many codes for that code length" }, 400);

      const codes = [];
      for (let i = 0; i < n; i++) {
        let code = null;
        for (let t = 0; t < 60; t++) {
          const c = String(Math.floor(Math.random() * space)).padStart(len, "0");
          if (!(await env.LIC.get("c:" + c))) { code = c; break; }
        }
        if (!code) break;
        const rec = { days, created: Date.now(), activated: null, revoked: false };
        await write(code, rec);
        codes.push({ code, ...rec });
      }
      return json({ codes });
    }

    // ── إداري: قائمة الأكواد ──
    if (action === "list") {
      if (!isAdmin()) return json({ error: "unauthorized" }, 401);

      const listed = await env.LIC.list({ prefix: "c:", limit: MAX_LIST });
      const codes = [];
      for (const k of listed.keys) {
        const rec = await read(k.name.slice(2));
        if (rec) codes.push({ code: k.name.slice(2), ...rec });
      }
      codes.sort((a, b) => (b.created || 0) - (a.created || 0));
      return json({ codes, truncated: !listed.list_complete });
    }

    // ── إداري: إيقاف رمز ──
    if (action === "revoke") {
      if (!isAdmin()) return json({ error: "unauthorized" }, 401);
      const code = (q.get("code") || "").trim();
      const rec = await read(code);
      if (!rec) return json({ ok: false, msg: "الرمز غير موجود." });
      rec.revoked = true;
      await write(code, rec);
      return json({ ok: true });
    }

    // ── إداري: تجديد رمز ──
    if (action === "extend") {
      if (!isAdmin()) return json({ error: "unauthorized" }, 401);
      const code = (q.get("code") || "").trim();
      const days = Math.min(Math.max(parseInt(q.get("days") || "365", 10), 1), 3650);
      const rec = await read(code);
      if (!rec) return json({ ok: false, msg: "الرمز غير موجود." });
      rec.days = days;
      rec.activated = Date.now();
      rec.revoked = false;
      await write(code, rec);
      return json({ ok: true, until: rec.activated + days * DAY });
    }

    return json({ ok: true, service: "daftara-license", version: 1 });
  },
};
