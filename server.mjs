import "dotenv/config";
import cors from "cors";
import express from "express";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { Api, TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions/index.js";
import { CustomFile } from "telegram/client/uploads.js";

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

app.use(express.json({ limit: "20mb" }));
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
  let srpRetries = 0;
  try {
    if (!item.client.connected) await item.client.connect();

    await item.client.signInWithPassword(
      { apiId: item.apiId, apiHash: item.apiHash },
      {
        password: async () => String(password),
        onError: async error => {
          const raw = errorText(error);

          // Telegram can invalidate the SRP id between account.GetPassword
          // and auth.CheckPassword. GramJS can safely retry the whole loop,
          // which fetches a fresh SRP id, when onError returns false.
          if (/SRP_ID_INVALID/i.test(raw) && srpRetries < 3) {
            srpRetries += 1;
            await new Promise(resolve => setTimeout(resolve, 500));
            return false;
          }

          authError = error;
          return true;
        }
      }
    );

    const authorized = await item.client.isUserAuthorized();
    if (!authorized) {
      throw new Error("2FA selesai tetapi sesi belum terotorisasi. Silakan minta OTP baru.");
    }

    await activateClient(item);
    return res.json({ ok: true, loggedIn: true, message: "Login 2FA berhasil." });
  } catch (error) {
    const actualError = authError || error;
    const raw = errorText(actualError);
    if (/SRP_ID_INVALID/i.test(raw)) {
      return res.status(409).json({
        error: "SRP Telegram kedaluwarsa. Klik Login & Ambil Grup untuk meminta OTP baru, lalu verifikasi OTP dan 2FA sekali lagi."
      });
    }
    return res.status(400).json({ error: friendlyTelegramError(actualError, "Password 2FA gagal diverifikasi.") });
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


// ---------------- SEND / MEDIA / NATIVE TELEGRAM SCHEDULER ----------------
// Pesan terjadwal dikirim ke Telegram sebagai scheduled message. Setelah
// Telegram menerima request schedule, PC/backend tidak perlu tetap aktif.
const sendJobs = new Map();
const MAX_MEDIA_BYTES = 10 * 1024 * 1024;
const MAX_GROUPS_PER_BATCH = 200;
const MIN_DELAY_SECONDS = 1;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function publicJob(job) {
  return {
    id: job.id,
    phone: job.phone,
    status: job.status,
    total: job.total,
    sent: job.sent,
    failed: job.failed,
    current: job.current || "",
    startedAt: job.startedAt,
    finishedAt: job.finishedAt || null,
    results: job.results.slice(-200)
  };
}

function cleanLinks(value) {
  if (!value) return [];
  if (!Array.isArray(value)) throw new Error("Format Link CTA tidak valid.");
  if (value.length > 3) throw new Error("Maksimal 3 Link CTA per pesan.");
  return value.map((item, index) => {
    const label = String(item?.label || "").trim().slice(0, 40);
    const rawUrl = String(item?.url || "").trim();
    if (!label || !rawUrl) throw new Error(`Link CTA ${index + 1} belum lengkap.`);
    let parsed;
    try { parsed = new URL(rawUrl); } catch { throw new Error(`URL Link CTA ${index + 1} tidak valid.`); }
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error(`URL Link CTA ${index + 1} harus http/https.`);
    return { label, url: parsed.toString() };
  });
}

function escapeMarkdownLabel(value) {
  return String(value).replace(/([\[\]\(\)])/g, "\\$1");
}

function messageWithLinks(message, links) {
  const base = String(message || "").trimEnd();
  const rows = cleanLinks(links).map(link => `🔗 [${escapeMarkdownLabel(link.label)}](${link.url})`);
  if (!rows.length) return base;
  return `${base}${base ? "\n\n" : ""}${rows.join("\n")}`;
}

function cleanMedia(media) {
  if (!media) return null;
  const name = String(media.name || "media.bin").replace(/[\\/]/g, "_").slice(0, 180);
  const mime = String(media.mime || "application/octet-stream").slice(0, 120);
  const data = String(media.data || "");
  const match = data.match(/^data:([^;]+);base64,(.+)$/s);
  const raw = match ? match[2] : data;
  if (!/^[A-Za-z0-9+/=\s]+$/.test(raw)) throw new Error("Format media tidak valid.");
  const buffer = Buffer.from(raw.replace(/\s/g, ""), "base64");
  if (!buffer.length) throw new Error("File media kosong.");
  if (buffer.length > MAX_MEDIA_BYTES) throw new Error("Media maksimal 10 MB per pengiriman.");
  return { name, mime, buffer };
}

async function getActiveAuthorized(phone) {
  const phoneKey = keyFor(phone);
  const item = active.get(phoneKey);
  if (!item) throw new Error("Akun Telegram belum login.");
  if (!item.client.connected) await item.client.connect();
  if (!(await item.client.isUserAuthorized())) {
    active.delete(phoneKey);
    await writeStoredSessions().catch(() => {});
    throw new Error("Sesi Telegram tidak valid. Silakan login ulang.");
  }
  return item;
}

async function dialogMap(client) {
  const dialogs = await client.getDialogs({ limit: 300 });
  const map = new Map();
  for (const d of dialogs) {
    if (!(d.isGroup || d.isChannel)) continue;
    map.set(String(d.id), { entity: d.entity, title: d.title || "Tanpa nama" });
  }
  return map;
}

async function sendOne(client, entity, message, media, scheduleUnix = undefined, links = []) {
  const content = messageWithLinks(message, links);
  if (media) {
    const file = new CustomFile(media.name, media.buffer.length, "", media.buffer);
    return client.sendFile(entity, {
      file,
      caption: content,
      parseMode: "md",
      schedule: scheduleUnix
    });
  }
  return client.sendMessage(entity, {
    message: content,
    parseMode: "md",
    schedule: scheduleUnix
  });
}

async function runImmediateJob(job, payload) {
  try {
    const item = await getActiveAuthorized(payload.phone);
    const groups = await dialogMap(item.client);
    const media = cleanMedia(payload.media);
    job.status = "running";
    const ids = payload.groupIds.slice(0, payload.maxGroups);
    for (let i = 0; i < ids.length; i++) {
      if (job.stopRequested) {
        job.status = "stopped";
        break;
      }
      const id = String(ids[i]);
      const target = groups.get(id);
      job.current = target?.title || id;
      if (!target) {
        job.failed++;
        job.results.push({ groupId: id, title: id, ok: false, error: "Grup tidak ditemukan pada akun aktif." });
      } else {
        try {
          await sendOne(item.client, target.entity, payload.message, media, undefined, payload.links);
          job.sent++;
          job.results.push({ groupId: id, title: target.title, ok: true });
        } catch (error) {
          job.failed++;
          job.results.push({ groupId: id, title: target.title, ok: false, error: friendlyTelegramError(error, "Gagal mengirim.") });
        }
      }
      if (i < ids.length - 1 && !job.stopRequested) await sleep(payload.delaySeconds * 1000);
    }
    if (job.status === "running") job.status = "done";
  } catch (error) {
    job.status = "failed";
    job.results.push({ ok: false, error: friendlyTelegramError(error, "Batch gagal.") });
  } finally {
    job.current = "";
    job.finishedAt = new Date().toISOString();
  }
}

function validateSendBody(body, scheduled = false) {
  const phone = String(body?.phone || "");
  const groupIds = Array.isArray(body?.groupIds) ? body.groupIds.map(String).filter(Boolean) : [];
  const message = String(body?.message || "");
  const delaySeconds = Math.max(MIN_DELAY_SECONDS, Math.min(3600, Number(body?.delaySeconds || 1)));
  const maxGroups = Math.max(1, Math.min(MAX_GROUPS_PER_BATCH, Number(body?.maxGroups || MAX_GROUPS_PER_BATCH)));
  if (!phoneOk(phone)) throw new Error("Nomor Telegram tidak valid.");
  if (!groupIds.length) throw new Error("Pilih minimal 1 grup.");
  if (!message.trim() && !body?.media && !(Array.isArray(body?.links) && body.links.length)) throw new Error("Isi pesan, pilih media, atau tambahkan Link CTA.");
  let scheduleAt = null;
  if (scheduled) {
    scheduleAt = new Date(body?.scheduleAt);
    if (Number.isNaN(scheduleAt.getTime())) throw new Error("Tanggal/jam schedule tidak valid.");
    if (scheduleAt.getTime() < Date.now() + 30_000) throw new Error("Jadwal minimal 30 detik dari sekarang.");
  }
  const links = cleanLinks(body?.links || []);
  return { phone, groupIds, message, delaySeconds, maxGroups, scheduleAt, media: body?.media || null, links };
}

app.post("/send/start", async (req, res) => {
  try {
    const payload = validateSendBody(req.body, false);
    await getActiveAuthorized(payload.phone);
    // Validasi media sebelum job dilepas ke background.
    if (payload.media) cleanMedia(payload.media);
    const id = crypto.randomUUID();
    const total = Math.min(payload.groupIds.length, payload.maxGroups);
    const job = {
      id, phone: payload.phone, status: "queued", total, sent: 0, failed: 0,
      current: "", stopRequested: false, startedAt: new Date().toISOString(), finishedAt: null, results: []
    };
    sendJobs.set(id, job);
    setImmediate(() => runImmediateJob(job, payload));
    return res.json({ ok: true, job: publicJob(job) });
  } catch (error) {
    return res.status(400).json({ error: friendlyTelegramError(error, "Tidak bisa memulai pengiriman.") });
  }
});

app.get("/send/jobs/:id", (req, res) => {
  const job = sendJobs.get(String(req.params.id));
  if (!job) return res.status(404).json({ error: "Job tidak ditemukan." });
  return res.json({ ok: true, job: publicJob(job) });
});

app.post("/send/jobs/:id/stop", (req, res) => {
  const job = sendJobs.get(String(req.params.id));
  if (!job) return res.status(404).json({ error: "Job tidak ditemukan." });
  if (["done", "failed", "stopped"].includes(job.status)) return res.json({ ok: true, job: publicJob(job) });
  job.stopRequested = true;
  job.status = "stopping";
  return res.json({ ok: true, job: publicJob(job) });
});

app.post("/schedule", async (req, res) => {
  try {
    const payload = validateSendBody(req.body, true);
    const item = await getActiveAuthorized(payload.phone);
    const groups = await dialogMap(item.client);
    const media = cleanMedia(payload.media);
    const ids = payload.groupIds.slice(0, payload.maxGroups);
    const baseUnix = Math.floor(payload.scheduleAt.getTime() / 1000);
    const results = [];
    let scheduledCount = 0;
    let failed = 0;

    for (let i = 0; i < ids.length; i++) {
      const id = String(ids[i]);
      const target = groups.get(id);
      if (!target) {
        failed++;
        results.push({ groupId: id, title: id, ok: false, error: "Grup tidak ditemukan." });
        continue;
      }
      try {
        // Telegram menyimpan scheduled message di server mereka. Delay dijadikan
        // selisih jadwal antar-grup, sehingga backend tidak perlu hidup pada waktu kirim.
        const scheduleUnix = baseUnix + (i * payload.delaySeconds);
        const msg = await sendOne(item.client, target.entity, payload.message, media, scheduleUnix, payload.links);
        scheduledCount++;
        results.push({ groupId: id, title: target.title, ok: true, messageId: msg?.id, scheduleUnix });
      } catch (error) {
        failed++;
        results.push({ groupId: id, title: target.title, ok: false, error: friendlyTelegramError(error, "Gagal menjadwalkan.") });
      }
    }
    return res.json({
      ok: failed === 0,
      scheduled: scheduledCount,
      failed,
      total: ids.length,
      scheduleAt: payload.scheduleAt.toISOString(),
      results
    });
  } catch (error) {
    return res.status(400).json({ error: friendlyTelegramError(error, "Tidak bisa membuat jadwal.") });
  }
});

await restoreSessions();
app.listen(PORT, () => console.log(`Telegram backend ready on port ${PORT}`));
