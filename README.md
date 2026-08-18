# Buzzer DivTelegram One — Backend Full

Fitur backend:
- Login Telegram akun dengan OTP + 2FA/SRP retry.
- Session terenkripsi dan restore otomatis.
- Sinkron grup/channel akun aktif.
- Kirim pesan langsung ke banyak grup.
- Kirim media + caption (maks. 10 MB per file).
- Delay antar grup dan batas jumlah grup.
- Stop batch kirim yang sedang berjalan.
- Scheduler memakai **native Telegram scheduled messages**: setelah schedule berhasil dibuat, Telegram yang menyimpan jadwalnya; PC tidak perlu menyala saat waktu kirim.

## Deploy Render
Upload semua file folder `backend` ini untuk mengganti backend lama, commit, lalu tunggu Render `Deploy live`.

Environment wajib:
- `MASTER_KEY`: string random minimal 32 karakter.
- `ALLOWED_ORIGINS`: domain frontend, atau kosong untuk pengujian.

Catatan: gunakan hanya pada grup/channel tempat akun Anda memang memiliki izin mengirim dan patuhi batas/rules Telegram.
