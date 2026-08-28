import "dotenv/config";
import cors from "cors";
import express from "express";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { Pool } from "pg";
import { Api, TelegramClient } from "telegram";
import { StringSession } from "telegram/sessions/index.js";
import { CustomFile } from "telegram/client/uploads.js";

const app = express();
const PORT = Number(process.env.PORT || 8787);
const allowed = (process.env.ALLOWED_ORIGINS || "").split(",").map(v=>v.trim()).filter(Boolean);
const MASTER_KEY = String(process.env.MASTER_KEY || "");
const APP_JWT_SECRET = String(process.env.APP_JWT_SECRET || MASTER_KEY || "");
const APP_INVITE_CODE = String(process.env.APP_INVITE_CODE || "");
const DATABASE_URL = String(process.env.DATABASE_URL || "");
const MAX_CONCURRENT_JOBS = Math.max(1, Math.min(20, Number(process.env.MAX_CONCURRENT_JOBS || 4)));
const MAX_USER_JOBS = Math.max(1, Math.min(5, Number(process.env.MAX_USER_JOBS || 1)));
const SESSION_TTL_MS = 10 * 60 * 1000;
const APP_SESSION_DAYS = Math.max(1, Math.min(3650, Number(process.env.APP_SESSION_DAYS || 365)));
const MAX_MEDIA_BYTES = 10 * 1024 * 1024;
const MAX_GROUPS_PER_BATCH = 200;
const MIN_DELAY_SECONDS = 1;
const DEV_STORE_FILE = process.env.SESSIONS_FILE || path.join(process.cwd(), "data", "multiuser-store.json");

if (MASTER_KEY.length < 32) throw new Error("MASTER_KEY minimal 32 karakter wajib diisi.");
if (APP_JWT_SECRET.length < 32) throw new Error("APP_JWT_SECRET minimal 32 karakter wajib diisi.");

const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } }) : null;
const pending = new Map();
const active = new Map();
const sendJobs = new Map();
const queue = [];
let runningJobs = 0;
const rateBuckets = new Map();

app.set("trust proxy", 1);
app.use(express.json({ limit: "20mb" }));
app.use(cors({
  origin(origin, cb) {
    if (!origin || allowed.length === 0 || allowed.includes(origin)) return cb(null, true);
    return cb(new Error("Origin tidak diizinkan"));
  }
}));

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const phoneOk = value => /^\+[1-9]\d{6,14}$/.test(String(value || ""));
const keyForPhone = value => String(value || "").replace(/[^\d+]/g, "");
const accountKey = (userId, phone) => `${userId}:${keyForPhone(phone)}`;
const b64url = b => Buffer.from(b).toString("base64url");

function errorText(error, fallback="Terjadi kesalahan Telegram.") { return String(error?.errorMessage || error?.message || fallback); }
function friendlyTelegramError(error, fallback) {
  const raw=errorText(error,fallback);
  if (/PASSWORD_HASH_INVALID/i.test(raw)) return "Password 2FA salah.";
  if (/PHONE_CODE_INVALID/i.test(raw)) return "Kode OTP salah.";
  if (/PHONE_CODE_EXPIRED/i.test(raw)) return "Kode OTP sudah kedaluwarsa. Minta kode baru.";
  if (/PHONE_NUMBER_INVALID/i.test(raw)) return "Nomor Telegram tidak valid.";
  if (/PHONE_PASSWORD_FLOOD/i.test(raw)) return "Telegram membatasi percobaan password/login. Jangan mencoba berulang; tunggu beberapa saat.";
  if (/FLOOD_WAIT_(\d+)/i.test(raw)) { const s=raw.match(/FLOOD_WAIT_(\d+)/i)?.[1]; return `Telegram membatasi request. Coba lagi sekitar ${s||"beberapa"} detik.`; }
  if (/AUTH_KEY_UNREGISTERED|SESSION_REVOKED|SESSION_EXPIRED/i.test(raw)) return "Sesi Telegram sudah tidak valid. Silakan login ulang.";
  return raw;
}

function aesKey(){ return crypto.createHash("sha256").update(MASTER_KEY).digest(); }
function encrypt(value){ const iv=crypto.randomBytes(12), c=crypto.createCipheriv("aes-256-gcm",aesKey(),iv); const enc=Buffer.concat([c.update(Buffer.from(String(value),"utf8")),c.final()]); return JSON.stringify({v:1,iv:b64url(iv),tag:b64url(c.getAuthTag()),data:b64url(enc)}); }
function decrypt(payload){ const p=typeof payload==="string"?JSON.parse(payload):payload; const d=crypto.createDecipheriv("aes-256-gcm",aesKey(),Buffer.from(p.iv,"base64url")); d.setAuthTag(Buffer.from(p.tag,"base64url")); return Buffer.concat([d.update(Buffer.from(p.data,"base64url")),d.final()]).toString("utf8"); }

function passwordHash(password, salt=crypto.randomBytes(16).toString("hex")){ const hash=crypto.scryptSync(String(password),salt,64).toString("hex"); return `${salt}:${hash}`; }
function passwordVerify(password, stored){ const [salt,hex]=String(stored||"").split(":"); if(!salt||!hex)return false; const a=Buffer.from(hex,"hex"),b=crypto.scryptSync(String(password),salt,a.length); return a.length===b.length&&crypto.timingSafeEqual(a,b); }
function signToken(user){ const header=b64url(JSON.stringify({alg:"HS256",typ:"JWT"})); const exp=Math.floor(Date.now()/1000)+APP_SESSION_DAYS*24*3600; const payload=b64url(JSON.stringify({sub:user.id,usr:user.username,exp})); const sig=crypto.createHmac("sha256",APP_JWT_SECRET).update(`${header}.${payload}`).digest("base64url"); return `${header}.${payload}.${sig}`; }
function verifyToken(token){ const [h,p,s]=String(token||"").split("."); if(!h||!p||!s) throw new Error("Token tidak valid."); const expected=crypto.createHmac("sha256",APP_JWT_SECRET).update(`${h}.${p}`).digest("base64url"); if(s.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(expected))) throw new Error("Token tidak valid."); const obj=JSON.parse(Buffer.from(p,"base64url").toString("utf8")); if(!obj.exp||obj.exp<Math.floor(Date.now()/1000)) throw new Error("Session dashboard kedaluwarsa."); return obj; }
function auth(req,res,next){ try{ const token=String(req.headers.authorization||"").replace(/^Bearer\s+/i,""); const p=verifyToken(token); req.user={id:p.sub,username:p.usr}; next(); }catch(e){ res.status(401).json({error:errorText(e,"Silakan login dashboard.")}); } }

function limiter({windowMs=60_000,max=120,key=(req)=>req.user?.id||req.ip}={}){ return (req,res,next)=>{ const k=key(req),now=Date.now(); let b=rateBuckets.get(k); if(!b||now-b.start>=windowMs)b={start:now,count:0}; b.count++; rateBuckets.set(k,b); if(b.count>max)return res.status(429).json({error:"Terlalu banyak request. Coba lagi sebentar."}); next(); }; }
app.use(limiter({max:240}));

async function initStore(){
  if(pool){
    await pool.query(`CREATE TABLE IF NOT EXISTS app_users(id UUID PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());`);
    await pool.query(`CREATE TABLE IF NOT EXISTS telegram_sessions(user_id UUID NOT NULL REFERENCES app_users(id) ON DELETE CASCADE,phone TEXT NOT NULL,api_id BIGINT NOT NULL,api_hash_enc TEXT NOT NULL,session_enc TEXT NOT NULL,updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(user_id,phone));`);
    await pool.query(`CREATE INDEX IF NOT EXISTS telegram_sessions_user_idx ON telegram_sessions(user_id);`);
  } else {
    try { await fs.access(DEV_STORE_FILE); } catch { await fs.mkdir(path.dirname(DEV_STORE_FILE),{recursive:true}); await fs.writeFile(DEV_STORE_FILE,JSON.stringify({users:[],sessions:[]},null,2)); }
    console.warn("DATABASE_URL belum diisi: memakai file store development. Untuk banyak user WAJIB gunakan PostgreSQL.");
  }
}
async function readDev(){ try{return JSON.parse(await fs.readFile(DEV_STORE_FILE,"utf8"));}catch{return {users:[],sessions:[]};} }
async function writeDev(v){ await fs.mkdir(path.dirname(DEV_STORE_FILE),{recursive:true}); await fs.writeFile(DEV_STORE_FILE,JSON.stringify(v,null,2)); }
async function createUser(username,password){
  const id=crypto.randomUUID(),ph=passwordHash(password);
  if(pool){ const r=await pool.query("INSERT INTO app_users(id,username,password_hash) VALUES($1,$2,$3) RETURNING id,username",[id,username,ph]); return r.rows[0]; }
  const db=await readDev(); if(db.users.some(x=>x.username.toLowerCase()===username.toLowerCase())) throw new Error("Nama pengguna sudah dipakai."); db.users.push({id,username,password_hash:ph}); await writeDev(db); return {id,username};
}
async function getUserByUsername(username){ if(pool){const r=await pool.query("SELECT id,username,password_hash FROM app_users WHERE lower(username)=lower($1)",[username]);return r.rows[0]||null;} const db=await readDev();return db.users.find(x=>x.username.toLowerCase()===String(username).toLowerCase())||null; }
async function saveSession(userId,{phone,apiId,apiHash,session}){
  if(pool){ await pool.query(`INSERT INTO telegram_sessions(user_id,phone,api_id,api_hash_enc,session_enc,updated_at) VALUES($1,$2,$3,$4,$5,NOW()) ON CONFLICT(user_id,phone) DO UPDATE SET api_id=EXCLUDED.api_id,api_hash_enc=EXCLUDED.api_hash_enc,session_enc=EXCLUDED.session_enc,updated_at=NOW()`,[userId,phone,apiId,encrypt(apiHash),encrypt(session)]); return; }
  const db=await readDev(); const i=db.sessions.findIndex(x=>x.user_id===userId&&x.phone===phone); const rec={user_id:userId,phone,api_id:apiId,api_hash_enc:encrypt(apiHash),session_enc:encrypt(session)}; if(i>=0)db.sessions[i]=rec;else db.sessions.push(rec);await writeDev(db);
}
async function loadSession(userId,phone){ if(pool){const r=await pool.query("SELECT phone,api_id,api_hash_enc,session_enc FROM telegram_sessions WHERE user_id=$1 AND phone=$2",[userId,phone]);const x=r.rows[0];if(!x)return null;return {phone:x.phone,apiId:Number(x.api_id),apiHash:decrypt(x.api_hash_enc),session:decrypt(x.session_enc)};} const db=await readDev();const x=db.sessions.find(s=>s.user_id===userId&&s.phone===phone);if(!x)return null;return {phone:x.phone,apiId:Number(x.api_id),apiHash:decrypt(x.api_hash_enc),session:decrypt(x.session_enc)}; }
async function deleteSession(userId,phone){ if(pool){await pool.query("DELETE FROM telegram_sessions WHERE user_id=$1 AND phone=$2",[userId,phone]);return;} const db=await readDev();db.sessions=db.sessions.filter(x=>!(x.user_id===userId&&x.phone===phone));await writeDev(db); }

app.get("/health",(_req,res)=>res.json({ok:true,service:"Buzzer DivTelegram One Multi-User API",database:pool?"postgres":"file-development",productionReady:!!pool,activeAccounts:active.size,runningJobs,queuedJobs:queue.length}));
app.post("/app/register",async(req,res)=>{ try{ const username=String(req.body?.username||"").trim();const password=String(req.body?.password||"");const invite=String(req.body?.inviteCode||""); if(username.length<3||username.length>40||!/^[A-Za-z0-9_.-]+$/.test(username))throw new Error("Username 3-40 karakter: huruf, angka, titik, garis bawah atau minus.");if(password.length<8)throw new Error("Password dashboard minimal 8 karakter.");if(APP_INVITE_CODE&&invite!==APP_INVITE_CODE)throw new Error("Kode undangan tidak valid.");if(await getUserByUsername(username))throw new Error("Nama pengguna sudah dipakai.");const user=await createUser(username,password);res.json({ok:true,token:signToken(user),user:{id:user.id,username:user.username}}); }catch(e){res.status(400).json({error:errorText(e,"Gagal mendaftar.")});} });
app.post("/app/login",async(req,res)=>{ try{const username=String(req.body?.username||"").trim();const password=String(req.body?.password||"");const user=await getUserByUsername(username);if(!user||!passwordVerify(password,user.password_hash))return res.status(401).json({error:"ID atau password dashboard tidak cocok."});res.json({ok:true,token:signToken(user),user:{id:user.id,username:user.username}});}catch(e){res.status(400).json({error:errorText(e,"Login gagal.")});} });
app.get("/app/me",auth,(req,res)=>res.json({ok:true,user:req.user}));

function cleanupPending(){const now=Date.now();for(const [k,item] of pending.entries()){if(now-item.createdAt>SESSION_TTL_MS){item.client?.disconnect?.().catch(()=>{});pending.delete(k);}}}
setInterval(cleanupPending,60_000).unref();

async function activateClient(userId,item){const k=accountKey(userId,item.phone);active.set(k,{...item,userId});pending.delete(k);await saveSession(userId,{phone:item.phone,apiId:item.apiId,apiHash:item.apiHash,session:item.client.session.save()});}
async function getActiveAuthorized(userId,phone){
  const k=accountKey(userId,phone);
  let item=active.get(k);
  if(!item){
    const rec=await loadSession(userId,String(phone));
    if(!rec)throw new Error("Akun Telegram belum login.");
    const client=new TelegramClient(new StringSession(rec.session),rec.apiId,rec.apiHash,{connectionRetries:5,autoReconnect:true});
    try{
      await client.connect();
      if(!(await client.isUserAuthorized())){
        await client.disconnect().catch(()=>{});
        // Jangan hapus session tersimpan otomatis. Session dapat gagal sementara karena jaringan/server.
        // Pengguna hanya perlu login ulang jika Telegram benar-benar mencabut session.
        throw new Error("Sesi Telegram belum dapat dipulihkan. Coba lagi beberapa saat; jika Telegram mencabut sesi, baru login ulang.");
      }
      item={...rec,client,userId};
      active.set(k,item);
      // Simpan ulang StringSession yang sudah tervalidasi agar database selalu punya session terbaru.
      await saveSession(userId,{phone:rec.phone,apiId:rec.apiId,apiHash:rec.apiHash,session:client.session.save()});
    }catch(e){
      active.delete(k);
      try{await client.disconnect();}catch{}
      throw e;
    }
  }
  try{
    if(!item.client.connected)await item.client.connect();
    if(!(await item.client.isUserAuthorized())){
      active.delete(k);
      try{await item.client.disconnect();}catch{}
      throw new Error("Sesi Telegram belum dapat dipulihkan. Coba lagi beberapa saat; jika Telegram mencabut sesi, baru login ulang.");
    }
    return item;
  }catch(e){
    active.delete(k);
    throw e;
  }
}

app.use("/auth",auth,limiter({max:60}));
app.use("/groups",auth);
app.use("/send",auth,limiter({max:120}));
app.use("/schedule",auth,limiter({max:60}));

app.post("/auth/send-code",async(req,res)=>{
  const {apiId,apiHash,phone}=req.body||{};
  if(!/^\d{4,12}$/.test(String(apiId))||!/^[a-f0-9]{32}$/i.test(String(apiHash))||!phoneOk(phone))return res.status(400).json({error:"API ID, API Hash, atau nomor Telegram tidak valid."});
  const k=accountKey(req.user.id,phone);
  try{
    // Sebelum mengirim OTP, coba pulihkan session lama dari PostgreSQL.
    // Jika masih valid, pengguna langsung masuk tanpa OTP/2FA ulang.
    try{
      const restored=await getActiveAuthorized(req.user.id,String(phone));
      if(restored)return res.json({ok:true,alreadyLoggedIn:true,loggedIn:true,message:"Sesi Telegram lama masih aktif. Login dipulihkan otomatis tanpa OTP."});
    }catch{}
    const old=pending.get(k);if(old?.client)await old.client.disconnect().catch(()=>{});
    const client=new TelegramClient(new StringSession(""),Number(apiId),String(apiHash),{connectionRetries:5,autoReconnect:true});
    await client.connect();
    const sent=await client.sendCode({apiId:Number(apiId),apiHash:String(apiHash)},String(phone));
    pending.set(k,{client,phone:String(phone),apiId:Number(apiId),apiHash:String(apiHash),phoneCodeHash:sent.phoneCodeHash,createdAt:Date.now()});
    res.json({ok:true,message:"Kode dikirim. Cek aplikasi Telegram atau SMS."});
  }catch(e){res.status(400).json({error:friendlyTelegramError(e,"Gagal meminta kode Telegram.")});}
});
app.post("/auth/verify-code",async(req,res)=>{const {phone,code}=req.body||{},k=accountKey(req.user.id,phone),item=pending.get(k);if(!item||Date.now()-item.createdAt>SESSION_TTL_MS)return res.status(400).json({error:"Sesi kode habis. Minta kode baru."});if(!/^\d{4,8}$/.test(String(code||"").trim()))return res.status(400).json({error:"Format kode OTP tidak valid."});try{await item.client.invoke(new Api.auth.SignIn({phoneNumber:item.phone,phoneCodeHash:item.phoneCodeHash,phoneCode:String(code).trim()}));await activateClient(req.user.id,item);res.json({ok:true,needsPassword:false,loggedIn:true});}catch(e){if(/SESSION_PASSWORD_NEEDED/i.test(errorText(e))){item.createdAt=Date.now();return res.json({ok:false,needsPassword:true,message:"OTP benar. Masukkan Password 2FA Telegram."});}res.status(400).json({error:friendlyTelegramError(e,"Kode OTP tidak valid.")});}});
app.post("/auth/password",async(req,res)=>{const {phone,password}=req.body||{},k=accountKey(req.user.id,phone),item=pending.get(k);if(!item||Date.now()-item.createdAt>SESSION_TTL_MS)return res.status(400).json({error:"Sesi 2FA habis. Minta kode OTP baru."});if(!String(password||"").length)return res.status(400).json({error:"Password 2FA belum diisi."});let authError=null,srpRetries=0;try{if(!item.client.connected)await item.client.connect();await item.client.signInWithPassword({apiId:item.apiId,apiHash:item.apiHash},{password:async()=>String(password),onError:async e=>{const raw=errorText(e);if(/SRP_ID_INVALID/i.test(raw)&&srpRetries<3){srpRetries++;await sleep(500);return false;}authError=e;return true;}});if(!(await item.client.isUserAuthorized()))throw new Error("2FA selesai tetapi sesi belum terotorisasi.");await activateClient(req.user.id,item);res.json({ok:true,loggedIn:true,message:"Login 2FA berhasil."});}catch(e){const a=authError||e;res.status(400).json({error:friendlyTelegramError(a,"Password 2FA gagal diverifikasi.")});}});
app.get("/auth/status",async(req,res)=>{const phone=String(req.query.phone||"");if(!phoneOk(phone))return res.json({ok:true,loggedIn:false});try{await getActiveAuthorized(req.user.id,phone);res.json({ok:true,loggedIn:true});}catch{res.json({ok:true,loggedIn:false});}});
app.post("/auth/logout",async(req,res)=>{const phone=String(req.body?.phone||""),k=accountKey(req.user.id,phone),item=active.get(k);if(item?.client){try{await item.client.invoke(new Api.auth.LogOut());}catch{}try{await item.client.disconnect();}catch{}}active.delete(k);pending.delete(k);await deleteSession(req.user.id,phone);res.json({ok:true});});
app.get("/groups",async(req,res)=>{try{const item=await getActiveAuthorized(req.user.id,String(req.query.phone||""));const dialogs=await item.client.getDialogs({limit:300});const groups=dialogs.filter(d=>d.isGroup||d.isChannel).map(d=>({id:String(d.id),title:d.title||"Tanpa nama"}));res.json({groups});}catch(e){res.status(401).json({error:friendlyTelegramError(e,"Gagal memuat grup.")});}});

function cleanLinks(value){if(!value)return[];if(!Array.isArray(value))throw new Error("Format Link CTA tidak valid.");if(value.length>3)throw new Error("Maksimal 3 Link CTA per pesan.");return value.map((item,index)=>{const label=String(item?.label||"").trim().slice(0,40),rawUrl=String(item?.url||"").trim();if(!label||!rawUrl)throw new Error(`Link CTA ${index+1} belum lengkap.`);let parsed;try{parsed=new URL(rawUrl);}catch{throw new Error(`URL Link CTA ${index+1} tidak valid.`);}if(!["http:","https:"].includes(parsed.protocol))throw new Error(`URL Link CTA ${index+1} harus http/https.`);return{label,url:parsed.toString()};});}
function escapeMarkdownLabel(v){return String(v).replace(/([\[\]\(\)])/g,"\\$1");}
function messageWithLinks(message,links){const base=String(message||"").trimEnd(),rows=cleanLinks(links).map(l=>`🔗 [${escapeMarkdownLabel(l.label)}](${l.url})`);return rows.length?`${base}${base?"\n\n":""}${rows.join("\n")}`:base;}
function cleanMedia(media){if(!media)return null;const name=String(media.name||"media.bin").replace(/[\\/]/g,"_").slice(0,180),data=String(media.data||""),match=data.match(/^data:([^;]+);base64,(.+)$/s),raw=match?match[2]:data;if(!/^[A-Za-z0-9+/=\s]+$/.test(raw))throw new Error("Format media tidak valid.");const buffer=Buffer.from(raw.replace(/\s/g,""),"base64");if(!buffer.length)throw new Error("File media kosong.");if(buffer.length>MAX_MEDIA_BYTES)throw new Error("Media maksimal 10 MB per pengiriman.");return{name,buffer};}
async function dialogMap(client){const dialogs=await client.getDialogs({limit:300});const map=new Map();for(const d of dialogs){if(d.isGroup||d.isChannel)map.set(String(d.id),{entity:d.entity,title:d.title||"Tanpa nama"});}return map;}
async function sendOne(client,entity,message,media,scheduleUnix,links=[]){const content=messageWithLinks(message,links);if(media){const file=new CustomFile(media.name,media.buffer.length,"",media.buffer);return client.sendFile(entity,{file,caption:content,parseMode:"md",schedule:scheduleUnix});}return client.sendMessage(entity,{message:content,parseMode:"md",schedule:scheduleUnix});}
function validateSendBody(body,scheduled=false){const phone=String(body?.phone||""),groupIds=Array.isArray(body?.groupIds)?body.groupIds.map(String).filter(Boolean):[],message=String(body?.message||""),delaySeconds=Math.max(MIN_DELAY_SECONDS,Math.min(3600,Number(body?.delaySeconds||1))),maxGroups=Math.max(1,Math.min(MAX_GROUPS_PER_BATCH,Number(body?.maxGroups||MAX_GROUPS_PER_BATCH)));if(!phoneOk(phone))throw new Error("Nomor Telegram tidak valid.");if(!groupIds.length)throw new Error("Pilih minimal 1 grup.");if(!message.trim()&&!body?.media&&!(Array.isArray(body?.links)&&body.links.length))throw new Error("Isi pesan, pilih media, atau tambahkan Link CTA.");let scheduleAt=null;if(scheduled){scheduleAt=new Date(body?.scheduleAt);if(Number.isNaN(scheduleAt.getTime()))throw new Error("Tanggal/jam schedule tidak valid.");if(scheduleAt.getTime()<Date.now()+30_000)throw new Error("Jadwal minimal 30 detik dari sekarang.");}return{phone,groupIds,message,delaySeconds,maxGroups,scheduleAt,media:body?.media||null,links:cleanLinks(body?.links||[])};}
function publicJob(j){return{id:j.id,status:j.status,total:j.total,sent:j.sent,failed:j.failed,current:j.current||"",startedAt:j.startedAt,finishedAt:j.finishedAt||null,results:j.results.slice(-200)};}
function userRunningCount(userId){let n=0;for(const j of sendJobs.values())if(j.userId===userId&&["queued","running","stopping"].includes(j.status))n++;return n;}
async function runImmediateJob(job,payload){try{const item=await getActiveAuthorized(job.userId,payload.phone),groups=await dialogMap(item.client),media=cleanMedia(payload.media);job.status="running";const ids=payload.groupIds.slice(0,payload.maxGroups);for(let i=0;i<ids.length;i++){if(job.stopRequested){job.status="stopped";break;}const id=String(ids[i]),target=groups.get(id);job.current=target?.title||id;if(!target){job.failed++;job.results.push({groupId:id,title:id,ok:false,error:"Grup tidak ditemukan pada akun aktif."});}else{try{await sendOne(item.client,target.entity,payload.message,media,undefined,payload.links);job.sent++;job.results.push({groupId:id,title:target.title,ok:true});}catch(e){job.failed++;job.results.push({groupId:id,title:target.title,ok:false,error:friendlyTelegramError(e,"Gagal mengirim.")});}}if(i<ids.length-1&&!job.stopRequested)await sleep(payload.delaySeconds*1000);}if(job.status==="running")job.status="done";}catch(e){job.status="failed";job.results.push({ok:false,error:friendlyTelegramError(e,"Batch gagal.")});}finally{job.current="";job.finishedAt=new Date().toISOString();runningJobs--;drainQueue();}}
function drainQueue(){while(runningJobs<MAX_CONCURRENT_JOBS&&queue.length){const x=queue.shift();if(x.job.stopRequested){x.job.status="stopped";x.job.finishedAt=new Date().toISOString();continue;}runningJobs++;setImmediate(()=>runImmediateJob(x.job,x.payload));}}
app.post("/send/start",async(req,res)=>{try{if(userRunningCount(req.user.id)>=MAX_USER_JOBS)return res.status(429).json({error:`Maksimal ${MAX_USER_JOBS} batch aktif per pengguna.`});const payload=validateSendBody(req.body,false);await getActiveAuthorized(req.user.id,payload.phone);if(payload.media)cleanMedia(payload.media);const id=crypto.randomUUID(),job={id,userId:req.user.id,phone:payload.phone,status:"queued",total:Math.min(payload.groupIds.length,payload.maxGroups),sent:0,failed:0,current:"",stopRequested:false,startedAt:new Date().toISOString(),finishedAt:null,results:[]};sendJobs.set(id,job);queue.push({job,payload});drainQueue();res.json({ok:true,job:publicJob(job)});}catch(e){res.status(400).json({error:friendlyTelegramError(e,"Tidak bisa memulai pengiriman.")});}});
app.get("/send/jobs/:id",(req,res)=>{const j=sendJobs.get(String(req.params.id));if(!j||j.userId!==req.user.id)return res.status(404).json({error:"Job tidak ditemukan."});res.json({ok:true,job:publicJob(j)});});
app.post("/send/jobs/:id/stop",(req,res)=>{const j=sendJobs.get(String(req.params.id));if(!j||j.userId!==req.user.id)return res.status(404).json({error:"Job tidak ditemukan."});if(!["done","failed","stopped"].includes(j.status)){j.stopRequested=true;j.status="stopping";}res.json({ok:true,job:publicJob(j)});});
app.post("/schedule",async(req,res)=>{try{const payload=validateSendBody(req.body,true),item=await getActiveAuthorized(req.user.id,payload.phone),groups=await dialogMap(item.client),media=cleanMedia(payload.media),ids=payload.groupIds.slice(0,payload.maxGroups),baseUnix=Math.floor(payload.scheduleAt.getTime()/1000),results=[];let scheduled=0,failed=0;for(let i=0;i<ids.length;i++){const id=String(ids[i]),target=groups.get(id);if(!target){failed++;results.push({groupId:id,title:id,ok:false,error:"Grup tidak ditemukan."});continue;}try{const scheduleUnix=baseUnix+i*payload.delaySeconds,msg=await sendOne(item.client,target.entity,payload.message,media,scheduleUnix,payload.links);scheduled++;results.push({groupId:id,title:target.title,ok:true,messageId:msg?.id,scheduleUnix});}catch(e){failed++;results.push({groupId:id,title:target.title,ok:false,error:friendlyTelegramError(e,"Gagal menjadwalkan.")});}}res.json({ok:failed===0,scheduled,failed,total:ids.length,scheduleAt:payload.scheduleAt.toISOString(),results});}catch(e){res.status(400).json({error:friendlyTelegramError(e,"Tidak bisa membuat jadwal.")});}});

setInterval(()=>{const cutoff=Date.now()-6*3600_000;for(const [id,j] of sendJobs.entries()){const t=Date.parse(j.finishedAt||j.startedAt);if(t<cutoff&&["done","failed","stopped"].includes(j.status))sendJobs.delete(id);}},30*60_000).unref();
await initStore();
app.listen(PORT,()=>console.log(`Buzzer DivTelegram One Multi-User ready on port ${PORT}`));
