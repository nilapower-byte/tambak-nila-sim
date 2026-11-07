# wanderIQ Nila

Game simulasi budidaya ikan nila 3D (Three.js). Bangun kolam, alirkan air, tebar benih, beri pakan, jaga oksigen dan amonia, lalu panen. Waktu game mengikuti jam HP.

## Berkas
- `index.html` : halaman web + game (satu berkas statis, tanpa build)
- `functions/api/[[path]].js` : API akun dan data pemain (Cloudflare Pages Functions)
- `schema.sql` : tabel database D1 (aman dijalankan ulang)
- `_headers` : header keamanan (CSP, HSTS, anti-iframe, dll). Letakkan di akar repo. Jika menambah sumber luar (skrip, font, gambar), tambahkan hostnya ke baris Content-Security-Policy

## Hosting di Cloudflare Pages
Workers & Pages → Create → Pages → Connect to Git → pilih repo ini.
- Build command: (kosong)
- Build output directory: `/`

## Aktifkan akun dan data per pengguna
1. Storage & Databases → D1 → Create database `nila-db` → Console → tempel isi `schema.sql` → Execute.
2. Pages project → Settings → Bindings → Add → D1 database. Variable name: `DB`. Pilih `nila-db`.
3. Commit `functions/api/[[path]].js` ke repo, tunggu deploy.

Cek: buka `/api/health`. Harus tampil `{"ok":true,"db":true}`.

Tanpa langkah di atas, game tetap jalan dengan data tersimpan di HP (tampil "Akun belum aktif").

## Akun
- Masuk/daftar dengan email dan kata sandi. Data tiap akun terpisah.
- Saat daftar, diberikan kode pemulihan (XXXX-XXXX-XXXX). Dipakai untuk "Lupa kata sandi". Kode baru bisa dibuat di Bantuan → Kode pemulihan.
- "Simpan akun": dicentang = tetap masuk ±30 hari; tidak dicentang = keluar saat browser ditutup.

## Referensi
SNI 7550:2009, SNI 6141:2009, Boyd & Tucker (1998), El-Sayed (2020), FAO Cultured Aquatic Species: Nile tilapia, Amal & Zamri-Saad (2011).

Copyright © Nov 2026 wanderIQ Nila
