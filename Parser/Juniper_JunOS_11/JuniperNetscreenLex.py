#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex


######## Modification of the class by Maurice TCHAMGOUE N. on 29-05-2015
###          * Adding the grammar to parse Routes

reserved = {
    r'host-name$': 'HOST_NAME',
    r'application$': 'APPLICATION',
    r'protocol$': 'PROTOCOL',
    r'destination-port$': 'DEST_PORT',
    r'address$': 'ADDRESS',
    r'address-set$': 'ADDRESS_SET',
    r'application-set$': 'APPLICATION_SET',
    r'icmp-code$': 'ICMP_CODE',
    r'policy$': 'POLICY',
    #r'match$': 'MATCH',
    r'source-address$': 'SRC_ADDR',
    r'destination-address$': 'DST_ADDR',
    r'permit$': 'PERMIT',
    r'reject$': 'REJECT',
    r'deny$' : 'DENY',
    r'unit$': 'UNIT',
    r'description$': 'DESCRIPTION',
    r'security-zone$': 'SECURITY_ZONE',
    r'from-zone$': 'FROM_ZONE',
    r'to-zone$': 'TO_ZONE',



}

tokens = [
             'PLUS',
             'HYPHEN',
             'SLASH',
             'IP_ADDR',
             'NUMBER',
             'WS',
             'NL',
             'WORD',
             'SEMI_COLON',
             'LBRACKET',
             'RBRACKET',
             'LBRACES',
             'RBRACES',
         ] + list(reserved.values())

def t_PLUS(t):
    r'\+'
    return t

def t_SEMI_COLON(t):
    r'\;'
    return t

def t_LBRACKET(t):
    r'\{'
    return t

def t_RBRACKET(t):
    r'\}'
    return t

def t_RBRACES(t):
    r'\]'
    return t

def t_LBRACES(t):
    r'\['
    return t

def t_HYPHEN(t):
    r'-'
    return t

def t_SLASH(t):
    r'/'
    return t

def t_IP_ADDR(t):
    r'\d+\.\d+\.\d+\.\d+'
    return t


def t_NUMBER(t):
    r'\d+'
    return t


def t_WS(t):
    r'[ \t]+'
    pass


def t_NL(t):
    r'[\n\r]+'
    return t


def t_WORD(t):
    r'(\"[^\"]+\")|[a-zA-Z0-9/\\\.,_-]+'
    # Check for reserved words
    for k, v in reserved.items():
        if re.match(k, t.value, re.I):
            t.type = v
    return t


def t_error(t):
    t.lexer.skip(1)
    return t


lexer = lex.lex()

if __name__ == '__main__':
    lex.runmain()

