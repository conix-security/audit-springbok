#!/usr/bin/python
__author__ = 'maurice'

from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Action import Action
from ROBDD.synthesis import synthesize
from ROBDD.synthesis import Bdd
import math

def is_subset(self, rule, test_rule):
        """r"""
        return len(synthesize(test_rule.toBDD(), Bdd.IMPL, rule.toBDD()).items) <= 2

def xor(x, y):
    return x ^ y

def PoidsFaible(y):
    z = 0
    for i in range(y):
        z += math.pow(2, i)
        return z

def PoidsFort(y):
    z = 0
    i = 8 - y
    while (i < 8):
        z += math.pow(2, i)
        i += 1
        return z

def inversion(x, y):
        y = y % 8
        i = PoidsFort(y)
        i = (x & int(i)) >> (8 - y)
        return ((i) + (x << y)) & 0x00ff # seems to be the modulo 256

def decrypt(clef, cleSaisie):
    resultat = ""
    for i in range(len(clef)):
        print i
        c = ord(clef[i])
        cr = ''
        if i != 0:
            t = ord(resultat[i - 1]) % 2
            if t == 0:
                cr = xor(c, ord(cleSaisie[i % len(cleSaisie)]))
                pass
            elif t == 1:
                cr = inversion(c, ord(cleSaisie[i % len(cleSaisie)]))
                pass
        else:
            cr = xor(c, ord(cleSaisie[i % len(cleSaisie)]))
            print cr
        resultat += chr(cr)
    return resultat

def verif(resultat):
    somme = 0
    for i in range(len(resultat)):
        somme += ord(resultat[i])
    if (somme == 8932):
        print resultat
    else:
        print "Mauvais mot de passe!"

clef = '\x71\x11\x24\x59\x8d\x6d\x71\x11\x35\x16\x8c\x6d\x71\x0d\x39\x47\x1f\x36\xf1\x2f\x39\x36\x8e\x3c\x4b\x39\x35\x12\x87\x7c\xa3\x10\x74\x58\x16\xc7\x71\x56\x68\x51\x2c\x8c\x73\x45\x32\x5b\x8c\x2a\xf1\x2f\x3f\x57\x6e\x04\x3d\x16\x75\x67\x16\x4f\x6d\x1c\x6e\x40\x01\x36\x93\x59\x33\x56\x04\x3e\x7b\x3a\x70\x50\x16\x04\x3d\x18\x73\x37\xac\x24\xe1\x56\x62\x5b\x8c\x2a\xf1\x45\x7f\x86\x07\x3e\x63\x47'

res =  decrypt(clef, 'amen')
print [car for car in res]

print verif(res)

from SpringBase.Ip import Ip

ip = Ip('192.168.255.1')
print 'to string', len(ip.to_string())
print 'get value', ip.get_value()
