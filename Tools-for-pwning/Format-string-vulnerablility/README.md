
SeeIn.py By Rev

# deskripsi

SeeIn.py adalah tools yang ku buat menggunakan bahasa Python, untuk sekarang aku buat secara open source, toh first tool. dengan tools ini diharapkan saat melakukan pwning dan menghadapi kerentanan format string tidak perlu repot repot scripting dari nol. tools ini akan melakukannya sendiri. brute force binary atau server ngatasi
untuk target tidak terbatas, bisa leak hingga 1024 index lebih dengan konsekuensi delay output. disarankan untuk hasil instant set targ ke 32 atau 64, jika kurang baru tambahin. segede apasi buffernya wkwkwkwk.

# compitable with :

* x86-64 binary not stripped

---

## Update v0.4 — apa yang berubah

Update kali ini agak gede wkwkkwk, banyak yang dirombak dari v0.3. Ringkasannya:

* **Batching system** — sekarang leak dikirim per-batch (`BATCH`), bukan sekaligus satu payload gede. Ini solusi buat kasus dimana buffer target kecil dan gampang overflow kalo payload-nya kepanjangan. Jadi kalo kena kasus target buffernya sempit, tinggal turunin `BATCH` (misal ke 2), bukan `TOINDEX`.
* **Payload dikecilin** — optimasi kecil di susunan payload, keitung 2 byte lebih hemat dibanding versi lama. Kecil emang, tapi lumayan kalo buffernya emang mepet-mepet banget.
* **Auto-skip index kosong** — kalo hasil leak-nya `(nil)` atau bukan hex valid, otomatis di-skip dari tabel biar gak ganggu analisis (fitur ini udah ada dari v0.3, tetep dipertahanin).
* **String preview (ASCII dump)** — tiap address yang ke-leak sekarang juga ditampilin representasi ASCII-nya di kolom `STRING` (mirip `hexdump`/gdb x/s), jadi kalo ada leak yang isinya string beneran (bukan cuma pointer), bisa langsung ketauan.
* **Deteksi index marker (`start idx`)** — otomatis ketauan index mana yang nunjuk balik ke buffer input kamu sendiri. Berguna banget buat nyari **offset** yang dipake di `fmtstr_payload(offset, {...})` milik pwntools — gak perlu nebak-nebak manual lagi.
* **Deteksi canary** (kalo binary punya canary aktif) dan **estimasi address `main`** otomatis kedeteksi dan ditandain di tabel, lengkap sama base offset-nya.
* **Byte tracking** — total byte yang dikirim, rata-rata byte per proses/batch, ditampilin di akhir. Berguna buat cross-check sama ukuran buffer target pas lagi nyari `BATCH` yang pas.
* **Spam payload generator** — otomatis generate payload `%p` spam sepanjang `TOINDEX`, lengkap sama marker index tiap kelipatan tertentu (`[IDX-N]`). Berguna kalo mau coba manual di gdb / nyari pola offset yang gak kecover sama leak normal.
* **Warning otomatis kalo error kebanyakan** — kalo jumlah leak yang gagal (`not hex`) udah lebih banyak dari yang berhasil, tools bakal ngasih warning nyaranin turunin `BATCH`. Ini biasanya tanda ada overflow/buffer kepenuhan.
* **Tampilan auto-width** — separator/section title (`─── [ LOG ] ───` dst) sekarang otomatis nyesuain lebar terminal kamu, jadi gak keliatan aneh kepotong atau ke gap-gap kayak sebelumnya. Mirip tampilan `gef`/`pwndbg`.
* **`INPUT_AFTER`** — dulu recvuntil-nya harus manual diedit langsung di kode (`p.recvuntil(b': ')`), sekarang tinggal atur di config atas doang.

---

tutorial pake tools SeeIn.py

source / download : [SeeIn.py](https://github.com/moonlitrepo/project/blob/main/Tools-for-pwning/Format-string-vulnerablility/SeeIn.py)

* set target binary / server di baris paling atas ada segmen target :

```
#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
BINARY = './vuln'  # RECOMENDED pake binary agar ga lag

TOINDEX = 64
BATCH = 2     # <-- bebas diatur

INPUT_AFTER = b':' # <- pasang karakter terakhir sebelum input
#============================#
```

deskripsi :

* `SERV` : server target (biasanya koneksi nc)
* `PORT` : port target
* `BINARY` : file binary lokal
* `TOINDEX` : leak sampe index ke berapa. normalnya set ke 32 atau 64. atau 67 bebas sih, antara 30 - 60 an
* `BATCH` : berapa index dikirim sekaligus per request. default 2. kalo target punya buffer kecil dan hasil leak-nya `N/A` semua, **turunin ini dulu** (coba 2 atau 4) sebelum nurunin `TOINDEX`
* `INPUT_AFTER` : byte terakhir sebelum program nunggu input (dulu harus edit manual di dalem kode, sekarang cukup di sini aja)

ini bebas di edit, binary untuk target lokal dan serv port untuk target server. tapi ga ku sarankan pake server ya soalnya biasanya ngeleg dan delay lama.
misal servernya adalah thpctf.net.id 50001 maka set `SERV = thpctf.net.id` dan `PORT = 50001`

* Cara menjalankan Tools jalankan dengan target server

```
python3 SeeIn.py
```

* tools ini bisa dijalankan dengan grep loh !

```
python3 SeeIn.py | grep canary
```

[!] jika server tidak valid, gagal dihubungi atau ngeleg, maka program akan otomatis menggunakan binary untuk me leak.

menjalankan secara lokal (target lokal binary)

```
python3 SeeIn.py LOCAL
```

* set titik input, cukup ganti `INPUT_AFTER` di config atas (gak perlu edit ke dalam fungsi lagi kayak versi lama):

misal pada binary

```
enter your input please:
```

maka atur

```
INPUT_AFTER = b'please:'
```
atau
```
INPUT_AFTER = b':'
```
---

## Jika hasil leak `N/A` semua / banyak yang gagal

Ini biasanya artinya buffer target kamu **kekecilan** buat nampung payload sekaligus banyak index — payload-nya overflow duluan sebelum sempet ke-print bersih sama `%p`. Tools bakal ngasih warning otomatis kalo ini kejadian (`jumlah error terlalu banyak, coba turunkan ukuran batch`).

Solusinya: **turunin `BATCH`**, bukan `TOINDEX`. Coba mulai dari `BATCH = 8`, kalo masih gagal turun ke `4`, terus `2`. Semakin kecil `BATCH`, semakin kecil juga payload yang dikirim per request — jadi lebih aman buat buffer sempit, cuma konsekuensinya makin banyak request yang harus dikirim (makin lama total prosesnya).

Cek juga bagian `Byte Sent` / `Avg sent per Process` di log akhir — itu bisa jadi patokan kasar buat bandingin sama ukuran buffer target kalo kamu udah tau dari analisis binary/gdb.

---

* ada beberapa leak mode :
* **start index** — nunjukin index yang balik nunjuk ke buffer input kamu sendiri. ini offset yang kamu pake buat `fmtstr_payload(offset, {...})`
* **canary** — otomatis kedeteksi kalo binary punya canary aktif
* **estimasi address `main`** — dan base offset-nya
* Estimasi Base address (belum di add untuk versi ini) 
* PIE (belum di add untuk versi ini)
* **stack** (masih tahap pengembangan)

contoh penggunaan

```
#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
BINARY = './vuln'  # RECOMENDED pake binary agar ga lag

TOINDEX = 64
BATCH = 2     # <-- bebas diatur

INPUT_AFTER = b':' # <- pasang karakter terakhir sebelum input
```
```
└> python3 SeeIn_v0.3.py LOCAL
```
<p align = "center"> <img width="1895" height="454" alt="image" src="https://github.com/user-attachments/assets/be2a5c80-c326-4db1-963b-b3cf94eaf49e" /> </p>

<p align = "center"><img width="1776" height="868" alt="image" src="https://github.com/user-attachments/assets/ca2fd5b6-beac-4f30-acc7-8aa7e2fca7fb" /> </p>


sekarang juga ada **spam payload** buat dipake manual kalo mau explore lebih jauh di gdb, lengkap sama marker `[IDX-N]` biar gampang nentuin index keberapa lagi diliat.

hope y enjoy it . ill always update it.

ini readme v 0.4
