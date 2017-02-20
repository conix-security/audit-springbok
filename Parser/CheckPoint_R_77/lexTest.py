__author__ = 'maurice'


import re
from ply import lex as lex

reserved = {
    r'netobj$': 'NETOBJ',
    r'type$': 'TYPE',
    r'bogus_ip$': 'BOGUS_IP',
    r'ipaddr_first$': 'IPADDR_FIRST',
    r'ipaddr_last$': 'IPADDR_LAST',
    r'netmask$': 'NETMASK',
    r'ipaddr$': 'IPADDR',
    r'track': 'TRACK',
    r'Uid': 'UID',
    r'location': 'LOCATION',
    r'add_addr_rule': 'ADD_ADDR_RULE',
    r'firewall': 'FIREWALL',
    r'floodgate': 'FLODDGATE',
    r'broadcast': 'BROADCAST',






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
            'LPAREN',
            'RPAREN',
            'COMA',


] + list(reserved.values())

def t_PLUS(t):
    r'\+'
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

def t_LPAREN(t):
    r'\('
    return t

def t_RPAREN(t):
    r'\)'
    return t

def t_COMA(t):
    r':'
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
