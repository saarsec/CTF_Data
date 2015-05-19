#!/usr/bin/env python
from pwn import *
import sys
context(arch='amd64', os='linux', timeout=2)

r = remote('mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me', 21249)

while True:
    res = r.recv()
    
    if res.startswith('You won!!!'):
        print res
        break
    
    print 'RECV', res[:-1]
    # normalize paranthesis
    res = res.replace('=', '').replace('[', '(').replace(']', ')').replace('{', '(').replace('}', ')')
    # words to numbers
    res = res.replace('ONE', '1').replace('TWO', '2').replace('THREE', '3').replace('FOUR', '4').replace('FIVE', '5').replace('SIX', '6').replace('SEVEN', '7').replace('EIGHT', '8').replace('NINE', '9').replace('ZERO', '0')
    res = res.replace ('^', '**')

    s = str(eval(res))
    print 'SEND', s
    r.sendline(s)
    print
