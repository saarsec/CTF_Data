#!/usr/bin/env python2.7
from pwn import *
import sys
import re
import math
context(arch='amd64', os='linux', timeout=2)

chars = '''ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ '''
charsInverted = chars[::-1]
rot = None

reExPass = re.compile('''Expected \[(.*)\] *$''')
rePass = re.compile('''Password \[(.*)\].*Expected''')

r = remote('blackbox_ced7f267475a0299446fa86c26d77161.quals.shallweplayaga.me', 18324)
sleep(0.15)
print r.recv()


# STEP 1, send char, get rotation offset
print 'Send: ', chars[:len(chars)/2]
r.sendline(chars[:len(chars)/2])
sleep(0.15)
res = r.recv()
print 'Recv: ', res
rot = chars.index(res[len('Password [')])
print 'Rotation: ', str(rot)

expected = reExPass.findall(res)[0]
password = ''
for c in expected:
    i = chars.index(c)
    i -= rot
    i %= len(chars)
    password += chars[i]

print 'Send: ', password
r.sendline(password)
sleep(0.15)
res = r.recv()
print 'Recv: ', res




# STEP 3, first char is ident, all others are based on the offset of all previous ones
r.sendline('')
sleep(0.15)
res = r.recv()
expected = reExPass.findall(res)[0]

password = '' + expected[0]
index = chars.index(expected[0])
for c in expected[1:]:
    i = chars.index(c)
    tmp = i - index
    tmp = tmp % len(chars)
    password += chars[tmp]
    index += i
print 'Send: ', password
r.sendline(password)
sleep(0.15)
res = r.recv()
print 'Recv: ', res
    
    


# STEP 3, like 1 but string is reversed
print 'Send: ', chars[:len(chars)/2]
r.sendline(chars[:len(chars)/2])
sleep(0.15)
res = r.recv()
print 'Recv: ', res
pas = rePass.findall(res)[0]
pas = pas[::-1]
rot = chars.index(pas[0])
#rot = charsInverted.index(res[len('Password [')])
print 'Rotation: ', str(rot)

expected = reExPass.findall(res)[0]
expected = expected[::-1]
password = ''
for c in expected:
    i = chars.index(c)
    i -= rot
    i %= len(chars)
    password += chars[i]

print 'Send: ', password
r.sendline(password)
sleep(0.15)
res = r.recv()
print 'Recv: ', res




# STEP 4, difference between consectutive chars, multiple of base diff + char index
print 'Send: ', 'AA'
r.sendline('AA')
sleep(0.15)
res = r.recv()
print 'Recv: ', res
pas = rePass.findall(res)[0]
charDiff = chars.index(pas[1]) - chars.index(pas[0])
print 'Char Diff: ', str(charDiff)

expected = reExPass.findall(res)[0]
password = '' + expected[0]
offset = 0
tmp = 1
for c in expected[1:]:
    i = chars.index(c)
    offset = -charDiff*tmp
    tmp += 1
    offset += i
    offset %= len(chars)
    password += chars[offset]

print 'Send: ', password
r.sendline(password)
sleep(0.15)
res = r.recv()
print 'Recv: ', res






# STEP 5
s = 'AAAAAXAA'
print 'Send: ', s
r.sendline(s)
sleep(0.15)
res = r.recv()
print 'Recv: ', res
pas = rePass.findall(res)[0]
rot = chars.index(pas[0]) - chars.index('A')
print 'Rotation: ', str(rot)

expected = reExPass.findall(res)[0]
password = ''
index = 0
i = 0
totalDelta = 0
for c in expected:
    ci = chars.index(c)
    chari = ci - 2**i * rot - totalDelta
    chari %= len(chars)
    password += chars[chari]
    i += 1
    totalDelta *= 2
    totalDelta += chari
password = password[::-1]

print 'Send: ', password
r.sendline(password)
r.recv()

# STEP 6
s = 'AA'
print 'Send: ', s
r.sendline(s)
sleep(0.15)
res = r.recv()
print 'Recv: ', res
pas= rePass.findall(res)[0]
rot = chars.index(pas[0])
print 'Rotation: ', str(rot)


r.interactive()
sleep(0.15)
res = r.recv()
print 'Recv: ', res

#charMap = {}
#midpoint = len(chars)/2
#r.interactive()
#
#print 'Send: ', chars[:midpoint]
#r.sendline(chars[:midpoint])
#sleep(0.15)
#res = r.recv()
#print 'Recv: ', res
#expected = reExPass.findall(res)[0]
#pas = rePass.findall(res)[0]
#for i in range(len(pas)):
#    charMap[res[i]] = chars[i]
#
#print 'Send: ', chars[midpoint:]
#r.sendline(chars[midpoint:])
#sleep(0.15)
#res = r.recv()
#print 'Recv: ', res
#pas = rePass.findall(res)[0]
#for i in range(len(pas)):
#    charMap[res[i]] = chars[midpoint+i]
#
#password = ''
#for c in expected:
#    password += charMap[c]
#
#print 'Send: ', password
#r.sendline(password)
#sleep(0.15)
#res = r.recv()
#print 'Recv: ', res





r.interactive()
sys.exit(0)
sleep(0.15)
res = r.recv()
print 'Recv: ', res

