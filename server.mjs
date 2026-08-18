import "dotenv/config";
import cors from "cors";
import express from "express";
import { TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions/index.js";

const app = express();
const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(v => v.trim()).filter(Boolean);
const pending = new Map();
const active = new Map();
app.use(express.json({ limit: "20kb" }));
app.use(cors({ origin(origin, cb) { if (!origin || allowed.length === 0 || allowed.includes(origin)) return cb(null, true); cb(new Error("Origin tidak diizinkan")); } }));

const phoneOk = value => /^\+[1-9]\d{6,14}$/.test(String(value || ""));
const keyFor = value => String(value || "").replace(/[^\d+]/g, "");

app.get("/health", (_req, res) => res.json({ ok: true, service: "Buzzer DivTelegram One Telegram API" }));

app.post("/auth/send-code", async (req, res) => {
  const { apiId, apiHash, phone } = req.body || {};
  if (!/^\d{4,12}$/.test(String(apiId)) || !/^[a-f0-9]{32}$/i.test(String(apiHash)) || !phoneOk(phone)) return res.status(400).json({ error: "API ID, API Hash, atau nomor Telegram tidak valid." });
  try {
    const client = new TelegramClient(new StringSession(""), Number(apiId), String(apiHash), { connectionRetries: 3 });
    await client.connect();
    const sent = await client.sendCode({ apiId: Number(apiId), apiHash: String(apiHash) }, String(phone));
    pending.set(keyFor(phone), { client, phone: String(phone), phoneCodeHash: sent.phoneCodeHash, createdAt: Date.now() });
    res.json({ ok: true, message: "Kode dikirim. Cek aplikasi Telegram atau SMS." });
  } catch (error) { res.status(400).json({ error: error?.message || "Gagal meminta kode Telegram." }); }
});

app.post("/auth/verify-code", async (req, res) => {
  const { phone, code } = req.body || {}; const item = pending.get(keyFor(phone));
  if (!item || Date.now() - item.createdAt > 10 * 60 * 1000) return res.status(400).json({ error: "Sesi kode habis. Minta kode baru." });
  try {
    await item.client.signIn({ phoneNumber: item.phone, phoneCodeHash: item.phoneCodeHash, phoneCode: String(code || "") });
    active.set(keyFor(phone), item.client); pending.delete(keyFor(phone));
    res.json({ ok: true, needsPassword: false });
  } catch (error) {
    const message = error?.message || "Kode tidak valid.";
    if (/SESSION_PASSWORD_NEEDED/i.test(message)) return res.json({ ok: false, needsPassword: true });
    res.status(400).json({ error: message });
  }
});

app.post("/auth/password", async (req, res) => {
  const { phone, password } = req.body || {}; const item = pending.get(keyFor(phone));
  if (!item || !password) return res.status(400).json({ error: "Sesi atau password 2FA tidak tersedia." });
  try { await item.client.signInWithPassword({ apiId: item.client.apiId, apiHash: item.client.apiHash }, { password: String(password) }); active.set(keyFor(phone), item.client); pending.delete(keyFor(phone)); res.json({ ok: true }); }
  catch (error) { res.status(400).json({ error: error?.message || "Password 2FA salah." }); }
});

app.get("/groups", async (req, res) => {
  const client = active.get(keyFor(req.query.phone)); if (!client) return res.status(401).json({ error: "Login Telegram belum selesai." });
  try { const dialogs = await client.getDialogs({ limit: 100 }); res.json({ groups: dialogs.filter(d => d.isGroup || d.isChannel).map(d => ({ id: String(d.id), title: d.title || "Tanpa nama" })) }); }
  catch (error) { res.status(400).json({ error: error?.message || "Gagal memuat grup." }); }
});

app.listen(process.env.PORT || 8787, () => console.log("Telegram backend ready"));
