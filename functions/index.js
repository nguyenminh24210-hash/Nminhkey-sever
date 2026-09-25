const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");

admin.initializeApp();
const db = admin.database();

const HMAC_SECRET = "novax_key"; // đổi nếu muốn
const ADMIN_TOKEN = "ADMIN_PASS_123"; // đổi thành pass mày muốn

exports.verify = functions.https.onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");

  const key = req.query.key;
  if (!key) return res.json({ valid: false, error: "Authentication failed" });

  try {
    const snap = await db.ref("keys/" + key.replace(/\./g, "_")).once("value");
    const data = snap.val();

    if (!data || !data.valid)
      return res.json({ valid: false, error: "Authentication failed" });

    const now = Math.floor(Date.now() / 1000);
    if (data.expires_at && data.expires_at < now)
      return res.json({ valid: false, error: "Key expired" });

    const payload = key + ":" + data.expires_at;
    const hmac = crypto
      .createHmac("sha256", HMAC_SECRET)
      .update(payload)
      .digest("base64");

    return res.json({ valid: true, expires_at: data.expires_at, hmac });
  } catch (e) {
    return res.json({ valid: false, error: "Server error" });
  }
});

exports.admin = functions.https.onRequest(async (req, res) => {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Headers", "Content-Type, x-admin-token");
  res.set("Access-Control-Allow-Methods", "POST, OPTIONS");

  if (req.method === "OPTIONS") return res.status(204).send("");

  if (req.headers["x-admin-token"] !== ADMIN_TOKEN)
    return res.status(403).json({ error: "Forbidden" });

  const { action, key, days, note } = req.body;

  try {
    if (action === "create") {
      const newKey = (key && key.trim()) ||
        "KEY-" + crypto.randomBytes(4).toString("hex").toUpperCase() +
        "-" + crypto.randomBytes(4).toString("hex").toUpperCase();
      const expiresAt = Math.floor(Date.now() / 1000) + (parseInt(days) || 30) * 86400;
      const safeKey = newKey.replace(/\./g, "_");
      await db.ref("keys/" + safeKey).set({
        valid: true,
        expires_at: expiresAt,
        created_at: Math.floor(Date.now() / 1000),
        note: note || ""
      });
      return res.json({ success: true, key: newKey, expires_at: expiresAt });
    }

    if (action === "delete") {
      await db.ref("keys/" + key.replace(/\./g, "_")).remove();
      return res.json({ success: true });
    }

    if (action === "toggle") {
      const safeKey = key.replace(/\./g, "_");
      const snap = await db.ref("keys/" + safeKey).once("value");
      const cur = snap.val();
      await db.ref("keys/" + safeKey).update({ valid: !cur.valid });
      return res.json({ success: true, valid: !cur.valid });
    }

    if (action === "extend") {
      const safeKey = key.replace(/\./g, "_");
      const newExpiry = Math.floor(Date.now() / 1000) + (parseInt(days) || 30) * 86400;
      await db.ref("keys/" + safeKey).update({ expires_at: newExpiry });
      return res.json({ success: true, expires_at: newExpiry });
    }

    if (action === "list") {
      const snap = await db.ref("keys").once("value");
      return res.json({ keys: snap.val() || {} });
    }

    return res.json({ error: "Unknown action" });
  } catch (e) {
    return res.json({ error: e.message });
  }
});
