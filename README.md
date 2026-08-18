# Buzzer DivTelegram One — Telegram Backend (2FA/SRP Fixed v2)

Backend Node.js/GramJS untuk login akun Telegram menggunakan OTP + Password 2FA.

## Perbaikan utama

- Kredensial `apiId` dan `apiHash` disimpan di sesi login sementara sehingga verifikasi 2FA memakai nilai yang benar.
- `signInWithPassword()` memakai callback `password` sesuai API GramJS.
- Error seperti password 2FA salah, OTP salah/kedaluwarsa, dan flood wait dibuat lebih jelas.
- Setelah login berhasil, `StringSession` disimpan terenkripsi AES-256-GCM memakai `MASTER_KEY`.
- Session yang masih valid dicoba dipulihkan ketika backend hidup kembali.
- Endpoint tambahan: `/auth/status` dan `/auth/logout`.
- `/groups` akan mencoba reconnect dan memeriksa authorization sebelum membaca daftar grup.

## Deploy di Render

Deploy folder ini sebagai **Node Web Service**.

Build command:

```bash
npm install
```

Start command:

```bash
npm start
```

Environment variables:

```env
ALLOWED_ORIGINS=https://DOMAIN-FRONTEND-KAMU
MASTER_KEY=buat-random-panjang-minimal-32-karakter
```

Set URL backend pada website:

```js
localStorage.setItem('divtelegramApi', 'https://URL-BACKEND-KAMU')
```

Lalu reload website.

## Alur login frontend

1. `POST /auth/send-code` → `{ apiId, apiHash, phone }`
2. `POST /auth/verify-code` → `{ phone, code }`
3. Jika respons `needsPassword: true`, panggil `POST /auth/password` → `{ phone, password }`
4. Jika `loggedIn: true`, panggil `GET /groups?phone=...`
5. Untuk cek session: `GET /auth/status?phone=...`
6. Logout: `POST /auth/logout` → `{ phone }`

## Catatan session pada Render

File session terenkripsi disimpan ke `data/sessions.enc.json`. Pada hosting dengan filesystem ephemeral, file bisa hilang ketika instance dibuat ulang/redeploy. Untuk persistence penuh 24/7, gunakan persistent disk/database atau hosting yang menyediakan storage persisten.

Jangan masukkan OTP atau Password 2FA ke `.env`, source code, atau chat. Jika API Hash pernah terlihat publik, buat kredensial API baru bila memungkinkan.


## Fix v2 — SRP_ID_INVALID

- Jika Telegram mengembalikan `SRP_ID_INVALID`, backend sekarang otomatis meminta parameter SRP baru dan mencoba ulang sampai 3 kali.
- `PASSWORD_HASH_INVALID` tetap langsung dihentikan dan dilaporkan sebagai password 2FA salah.
- Setelah 2FA, backend memastikan sesi benar-benar authorized sebelum menyimpannya.
