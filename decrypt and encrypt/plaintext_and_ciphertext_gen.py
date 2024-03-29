#!/usr/bin/env python
from Crypto.Cipher import AES
import sys

def b_to_num(message):
    #converts bytes to nums
    num = []
    for i in range(0, len(message)):
        num.append(int(message[i].encode('hex'), 16))
    return num

def num_to_b(num):
    b = []
    for i in range(0, len(num)):
        b.append(chr(num[i]))
    return b
    

def pad(message):
    #pads a message BEFORE encryption
    topad = 16 - (len(message) % 16)
    for i in range(0, topad):
        message += chr(topad)
    return message

def check_pad(message):
    #checks the padding of a message AFTER decryption
    mnum = b_to_num(message)
    wantpad = mnum[-1]
    for i in range(0, wantpad):
        if (mnum[-1-i] != wantpad):
            return 0
    return 1
    
key = 'COMP3632 testkey'
iv =  'COMP3111 test iv'
obj = AES.new(key, AES.MODE_CBC, iv)
message = "Message block1  Message block2"
message = pad(message)
g = open("padded_plaintext", "wb")
g.write(message)
g.close()
##print message
##print check_pad(message)
ciphertext = obj.encrypt(message)
f = open("ciphertext", "wb")
f.write(iv)
f.write(ciphertext)
f.close()
