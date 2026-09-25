# README.md

SeeIn.py By Rev

## deskripsi
SeeIn.py adalah tools yang ku buat menggunakan bahasa Python, untuk sekarang aku buat secara open source, toh first tool. dengan tools ini diharapkan saat melakukan pwning
dan menghadapi kerentanan format string tidak perlu repot repot scripting dari nol. tools ini akan melakukannya sendiri. brute force binary atau server ngatasi

untuk target tidak terbatas, bisa leak hingga 1024 index lebih dengan konsekuensi delay output. disarankan untuk hasil instant set targ ke 32 atau 64, jika kurang baru tambahin.
segede apasi buffernya wkwkwkwk.


## tutorial pake tools SeeIn.py

source / download : [SeeIn.py](SeeIn.py)

- **set target binary / server**
di baris paling atas ada segmen target :

```Python
#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
BINARY = './vuln' 
TOINDEX = 64
#============================#
```

deskripsi :
- SERV : server target (biasanya koneksi nc)
- PORT : port target
- BINARY : file binary lokal
- TOINDEX : leak sampe index ke berapa. normalnya set ke 32 atau 64. atau 67 bebas sih, antara 30 - 60 an 

ini bebas di edit, binary untuk target lokal dan serv port untuk target server. **tapi ga ku sarankan pake server ya soalnya biasanya ngeleg dan delay lama.**

misal servernya adalah **thpctf.net.id 50001**  maka set SERV = thpctf.net.id dan PORT = 50001  


- **Cara menjalankan Tools**
jalankan dengan target server 
```
python3 SeeIn.py
```
[!] jika server tidak valid, gagal dihubungi atau ngeleg, maka program akan otomatis menggunakan binary untuk me leak.


menjalankan secara lokal (target lokal binary)
```
python3 SeeIn.py LOCAL
```
- **set sendline point**
```Python
           #===[ sendline segment 1 ]===#
        p.recvuntil(b': ')
        p.sendline(pay.encode())
```
atur p.recvuntil ke byte terakhir sebelum input.

misal pada binary 
```
enter your input please 
```
maka atur recvuntil jadi 
```
p.recvuntil(b'please')
```


- ada beberapa leak mode :
- start index : input disimpan / awal stack
- Estimasi Base address (standart off / komentar)
- PIE (standart off / komentar)
- CANARY
- MAIN + calculate BASE ADDR


# contoh penggunaan
<p align = "center"> <img width="75%" height="1078" alt="image" src="https://github.com/user-attachments/assets/414b5624-af92-405c-bb09-9a50f17cd800" />
</p>
aku akan segera update tampilan leaknya, ini agak boros layar wkwkwkkw

namun kejutannya ada di akhir :
<p align = "center"> <img width="75%" height="1039" alt="image" src="https://github.com/user-attachments/assets/9e6e6f58-6844-4ace-8693-765b99d593f3" />
</p>

terdapat semacam tabel / kesimpulan jir keren bgt gg .

selain itu sadar ga si? indexnya lompat lompat, itu karena program ini otomatis melompati index yang hanya berisi kosong / bukan value hex. biasanya kalo di leak itu `(nil)`
itu hanya akan mengganggu analisis ya kan? jadi ku hapus aja. 

dan ada juga payload maker , berguna banget kan? wkwkkwkwkkwkwkkwkw

hope y enjoy it . ill always update it.

