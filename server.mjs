import "dotenv/config";
import cors from "cors";
import express from "express";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { Api, TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions/index.js";

const app = express();
const PORT = Number(process.env.PORT || 8787);
const allowed = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

const pending = new Map();
const active = new Map();
const SESSION_TTL_MS = 10 * 60 * 1000;
const SESSIONS_FILE = process.env.SESSIONS_FILE || path.join(process.cwd(), "data", "sessions.enc.json");

app.use(express.json({ limit: "20kb" }));
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowed.length === 0 || allowed.includes(origin)) return cb(null, true);
    return cb(new Error("Origin tidak diizinkan"));
  }
}));

const phoneOk = value => /^\+[1-9]\d{6,14}$/.test(String(value || ""));
const keyFor = value => String(value || "").replace(/[^\d+]/g, "");

function errorText(error, fallback = "Terjadi kesalahan Telegram.") {
  return String(error?.errorMessage || error?.message || fallback);
}

function friendlyTelegramError(error, fallback) {
  const raw = errorText(error, fallback);
  if (/PASSWORD_HASH_INVALID/i.test(raw)) return "Password 2FA salah.";
  if (/PHONE_CODE_INVALID/i.test(raw)) return "Kode OTP salah.";
  if (/PHONE_CODE_EXPIRED/i.test(raw)) return "Kode OTP sudah kedaluwarsa. Minta kode baru.";
  if (/PHONE_NUMBER_INVALID/i.test(raw)) return "Nomor Telegram tidak valid.";
  if (/FLOOD_WAIT_(\d+)/i.test(raw)) {
    const seconds = raw.match(/FLOOD_WAIT_(\d+)/i)?.[1];
    return `Telegram membatasi percobaan login. Coba lagi sekitar ${seconds || "beberapa"} detik.`;
  }
  if (/AUTH_KEY_UNREGISTERED|SESSION_REVOKED|SESSION_EXPIRED/i.test(raw)) return "Sesi Telegram sudah tidak valid. Silakan login ulang.";
  return raw;
}

function masterKey() {
  const raw = String(process.env.MASTER_KEY || "");
  if (raw.length < 32) return null;
  return crypto.createHash("sha256").update(raw).digest();
}

function encryptJson(value) {
  const key = masterKey();
  if (!key) throw new Error("MASTER_KEY minimal 32 karakter diperlukan untuk menyimpan sesi.");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    v: 1,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    data: encrypted.toString("base64")
  };
}

function decryptJson(payload) {
  const key = masterKey();
  if (!key) throw new Error("MASTER_KEY tidak tersedia.");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(payload.iv, "base64"));
  decipher.setAuthTag(Buffer.from(payload.tag, "base64"));
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(payload.data, "base64")),
    decipher.final()
  ]);
  return JSON.parse(decrypted.toString("utf8"));
}

async function readStoredSessions() {
  try {
    const raw = await fs.readFile(SESSIONS_FILE, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.map(decryptJson) : [];
  } catch (error) {
    if (error?.code !== "ENOENT") console.error("Gagal membaca session store:", errorText(error));
    return [];
  }
}

async function writeStoredSessions() {
  const records = [];
  for (const [phoneKey, item] of active.entries()) {
    const session = item.client?.session?.save?.();
    if (!session) continue;
    records.push(encryptJson({
      phone: item.phone || phoneKey,
      apiId: item.apiId,
      apiHash: item.apiHash,
      session
    }));
  }
  await fs.mkdir(path.dirname(SESSIONS_FILE), { recursive: true });
  await fs.writeFile(SESSIONS_FILE, JSON.stringify(records, null, 2), "utf8");
}

async function activateClient({ phone, apiId, apiHash, client }) {
  const phoneKey = keyFor(phone);
  active.set(phoneKey, { phone: String(phone), apiId: Number(apiId), apiHash: String(apiHash), client });
  pending.delete(phoneKey);
  await writeStoredSessions();
}

async function restoreSessions() {
  const records = await readStoredSessions();
  for (const record of records) {
    try {
      if (!phoneOk(record.phone) || !record.apiId || !record.apiHash || !record.session) continue;
      const client = new TelegramClient(
        new StringSession(String(record.session)),
        Number(record.apiId),
        String(record.apiHash),
        { connectionRetries: 3 }
      );
      await client.connect();
      const authorized = await client.isUserAuthorized();
      if (!authorized) {
        await client.disconnect();
        continue;
      }
      active.set(keyFor(record.phone), {
        phone: String(record.phone),
        apiId: Number(record.apiId),
        apiHash: String(record.apiHash),
        client
      });
      console.log(`Session restored: ${record.phone}`);
    } catch (error) {
      console.error("Gagal restore session:", friendlyTelegramError(error));
    }
  }
}

function cleanupPending() {
  const now = Date.now();
  for (const [key, item] of pending.entries()) {
    if (now - item.createdAt > SESSION_TTL_MS) {
      item.client?.disconnect?.().catch(() => {});
      pending.delete(key);
    }
  }
}
setInterval(cleanupPending, 60_000).unref();

app.get("/health", (_req, res) => res.json({
  ok: true,
  service: "Buzzer DivTelegram One Telegram API",
  activeAccounts: active.size
}));

app.post("/auth/send-code", async (req, res) => {
  const { apiId, apiHash, phone } = req.body || {};
  if (!/^\d{4,12}$/.test(String(apiId)) || !/^[a-f0-9]{32}$/i.test(String(apiHash)) || !phoneOk(phone)) {
    return res.status(400).json({ error: "API ID, API Hash, atau nomor Telegram tidak valid." });
  }

  const phoneKey = keyFor(phone);
  try {
    const previous = pending.get(phoneKey);
    if (previous?.client) await previous.client.disconnect().catch(() => {});

    const client = new TelegramClient(
      new StringSession(""),
      Number(apiId),
      String(apiHash),
      { connectionRetries: 3 }
    );
    await client.connect();

    const sent = await client.sendCode(
      { apiId: Number(apiId), apiHash: String(apiHash) },
      String(phone)
    );

    pending.set(phoneKey, {
      client,
      phone: String(phone),
      apiId: Number(apiId),
      apiHash: String(apiHash),
      phoneCodeHash: sent.phoneCodeHash,
      createdAt: Date.now()
    });

    return res.json({ ok: true, message: "Kode dikirim. Cek aplikasi Telegram atau SMS." });
  } catch (error) {
    return res.status(400).json({ error: friendlyTelegramError(error, "Gagal meminta kode Telegram.") });
  }
});

app.post("/auth/verify-code", async (req, res) => {
  const { phone, code } = req.body || {};
  const phoneKey = keyFor(phone);
  const item = pending.get(phoneKey);

  if (!item || Date.now() - item.createdAt > SESSION_TTL_MS) {
    return res.status(400).json({ error: "Sesi kode habis. Minta kode baru." });
  }
  if (!/^\d{4,8}$/.test(String(code || "").trim())) {
    return res.status(400).json({ error: "Format kode OTP tidak valid." });
  }

  try {
    await item.client.invoke(new Api.auth.SignIn({
      phoneNumber: item.phone,
      phoneCodeHash: item.phoneCodeHash,
      phoneCode: String(code).trim()
    }));

    await activateClient(item);
    return res.json({ ok: true, needsPassword: false, loggedIn: true });
  } catch (error) {
    const raw = errorText(error);
    if (/SESSION_PASSWORD_NEEDED/i.test(raw)) {
      item.createdAt = Date.now();
      return res.json({ ok: false, needsPassword: true, message: "OTP benar. Masukkan Password 2FA Telegram." });
    }
    return res.status(400).json({ error: friendlyTelegramError(error, "Kode OTP tidak valid.") });
  }
});

app.post("/auth/password", async (req, res) => {
  const { phone, password } = req.body || {};
  const phoneKey = keyFor(phone);
  const item = pending.get(phoneKey);

  if (!item || Date.now() - item.createdAt > SESSION_TTL_MS) {
    return res.status(400).json({ error: "Sesi 2FA habis. Minta kode OTP baru." });
  }
  if (!String(password || "").length) {
    return res.status(400).json({ error: "Password 2FA belum diisi." });
  }

  let authError = null;
  try {
    await item.client.signInWithPassword(
      { apiId: item.apiId, apiHash: item.apiHash },
      {
        password: async () => String(password),
        onError: async error => {
          authError = error;
          return true;
        }
      }
    );

    await activateClient(item);
    return res.json({ ok: true, loggedIn: true, message: "Login 2FA berhasil." });
  } catch (error) {
    const actualError = authError || error;
    return res.status(400).json({ error: friendlyTelegramError(actualError, "Password 2FA salah.") });
  }
});

app.get("/auth/status", async (req, res) => {
  const phoneKey = keyFor(req.query.phone);
  const item = active.get(phoneKey);
  if (!item) return res.json({ ok: true, loggedIn: false });
  try {
    if (!item.client.connected) await item.client.connect();
    const loggedIn = await item.client.isUserAuthorized();
    return res.json({ ok: true, loggedIn });
  } catch {
    return res.json({ ok: true, loggedIn: false });
  }
});

app.post("/auth/logout", async (req, res) => {
  const phoneKey = keyFor(req.body?.phone);
  const item = active.get(phoneKey);
  if (item?.client) {
    try { await item.client.invoke(new Api.auth.LogOut()); } catch { /* session may already be invalid */ }
    try { await item.client.disconnect(); } catch { /* ignore */ }
  }
  active.delete(phoneKey);
  pending.delete(phoneKey);
  try { await writeStoredSessions(); } catch (error) { console.error("Gagal menyimpan perubahan logout:", errorText(error)); }
  return res.json({ ok: true });
});

app.get("/groups", async (req, res) => {
  const phoneKey = keyFor(req.query.phone);
  const item = active.get(phoneKey);
  if (!item) return res.status(401).json({ error: "Login Telegram belum selesai." });

  try {
    if (!item.client.connected) await item.client.connect();
    if (!(await item.client.isUserAuthorized())) {
      active.delete(phoneKey);
      await writeStoredSessions().catch(() => {});
      return res.status(401).json({ error: "Sesi Telegram tidak valid. Silakan login ulang." });
    }

    const dialogs = await item.client.getDialogs({ limit: 200 });
    const groups = dialogs
      .filter(d => d.isGroup || d.isChannel)
      .map(d => ({ id: String(d.id), title: d.title || "Tanpa nama" }));

    return res.json({ groups });
  } catch (error) {
    return res.status(400).json({ error: friendlyTelegramError(error, "Gagal memuat grup.") });
  }
});

await restoreSessions();
app.listen(PORT, () => console.log(`Telegram backend ready on port ${PORT}`));
