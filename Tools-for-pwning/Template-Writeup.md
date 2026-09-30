# [Nama Challenge]

> Cara pakai template ini: isi tiap `[...]` dengan konten kamu. Bagian yang ditandai
> **(opsional/potong kalau waktu mepet)** boleh dipadatkan atau dihilangkan untuk chall
> level easy. Bagian tanpa tanda itu **wajib ada** karena biasanya masuk poin penilaian.

## Deskripsi

```
name: "[nama chall]"
category: [Binary Exploitation / Pwn]
description: |-
  [deskripsi dari soal]

connection_info: [nc host port]
tags:
  - [easy/medium/hard]
```

## Summary

[1-3 kalimat: chall ini punya kerentanan apa, dan apa yang berhasil dicapai
(dapat shell? RCE? baca flag langsung?). Ini paragraf "ringkasan eksekutif" —
juri yang buru-buru baca ini dulu, jadi harus jelas dan padat.]

## Vulnerable

[List semua kerentanan yang ditemukan, walau tidak semua dipakai. Urutkan
dari yang ditemukan duluan / yang paling signifikan.]

1. [nama vuln 1 — pakai istilah presisi, bukan "aneh"/"rentan akses shell". 
   Kalau bingung penamaan, cek CWE: cwe.mitre.org]
2. [nama vuln 2]
3. ...

## Analysis

### Fast check **(boleh dipadatkan untuk chall easy)**

```
file [binary] ; pwn checksec [binary]
```

[Tempel hasil checksec. Lalu 1-2 kalimat: proteksi apa yang mati, dan
kenapa itu relevan ke strategi exploit nanti — jangan cuma tempel output
tanpa komentar.]

### Eksplorasi awal / dynamic analysis **(padatkan jadi kesimpulan langsung untuk chall easy)**

[Kalau pakai ltrace/strace/gdb buat investigasi awal, cukup 1 paragraf:
apa yang dicari, apa yang ditemukan. Hindari narasi "saya coba ini, lalu itu,
ternyata..." kalau bisa langsung disimpulkan.

Contoh versi padat:
"Analisis dinamis menggunakan `ltrace` menunjukkan validasi PIN dilakukan
via `strcmp()` terhadap string hardcoded, yang terekam plaintext di trace."]

### Source code / decompile analysis

[Tempel source/pseudocode yang RELEVAN saja — potong bagian yang tidak
menambah pemahaman (misal baris `local_78[x] = '\0'` yang berulang 40x
bisa disingkat jadi 1 baris komentar "diisi nol sepanjang 0x28 byte").]

```c
[source code relevan]
```

**Root cause:** [jelaskan singkat kenapa ini vuln — 1-2 kalimat per vuln]

### Vuln yang ditemukan tapi tidak dipakai **(wajib disebut, tapi singkat — 2-4 kalimat saja)**

[Untuk tiap vuln sekunder: apa bug-nya, potensi dampak, kenapa tidak dipakai/
kenapa vuln lain lebih efisien. Jangan kasih porsi sama seperti vuln utama.]

## Rencana Eksploitasi

[Bullet point pendek, bukan paragraf — ini bagian yang paling enak dibaca
dalam bentuk list karena sifatnya sekuensial.]

- [langkah 1]
- [langkah 2]
- [langkah 3]

## Exploit

```python
[script exploit — sertakan komentar singkat per bagian penting, terutama
perhitungan offset/payload]
```

**Bukti keberhasilan:**

```
[output terminal / hasil koneksi ke server yang menunjukkan shell/flag didapat]
```

Flag: **[flag]**

## Rekomendasi Mitigasi

[Untuk TIAP vuln di section "Vulnerable" — urutannya harus sama biar gampang
dilacak. Format: akar masalah -> perbaikan kode -> (opsional) mitigasi
level compiler/OS.]

1. [nama vuln 1]

   **Akar masalah:** [kenapa bug ini bisa terjadi]

   **Perbaikan:**
   ```c
   // Rentan
   [kode rentan]

   // Aman
   [kode aman]
   ```

2. [nama vuln 2]

   **Akar masalah:** [...]

   **Perbaikan:**
   ```c
   // Rentan
   [...]

   // Aman
   [...]
   ```

3. Mitigasi tambahan pada level kompilasi/sistem

   | Proteksi | Status di Binary | Fungsi |
   |---|---|---|
   | Stack Canary | [aktif/tidak] | Mendeteksi modifikasi *return address* |
   | NX | [aktif/tidak] | Mencegah eksekusi kode di stack/heap |
   | PIE | [aktif/tidak] | Mengacak base address binary |
   | RELRO | [full/partial/none] | Melindungi GOT dari overwrite |

   ```bash
   gcc -fstack-protector-all -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack source.c -o binary
   ```

---

## Checklist sebelum submit

- [ ] Penomoran list di semua section urut (gak ada yang loncat)
- [ ] Format angka konsisten (hex vs desimal, pilih satu gaya per konteks)
- [ ] Semua vuln di "Vulnerable" ada pasangannya di "Rekomendasi Mitigasi"
- [ ] Bahasa formal, tidak ada kata santai (bikin/nge-/gitu/dong)
- [ ] Kode contoh (rentan/aman) sudah dicek valid secara sintaks, atau
      diberi catatan "(disederhanakan dari hasil dekompilasi)" kalau memang
      pseudo-code
- [ ] Flag/bukti keberhasilan sudah ditempel
