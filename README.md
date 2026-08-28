# Buzzer DivTelegram One - Multi User Production

Backend Node.js dengan autentikasi dashboard server-side, isolasi session Telegram per user, PostgreSQL session store, queue pengiriman, rate limit, dan scheduler Telegram native.

Untuk pemakaian banyak user, isi DATABASE_URL PostgreSQL. Tanpa DATABASE_URL backend jatuh ke file-store development dan **tidak direkomendasikan untuk production/multi-instance**.
