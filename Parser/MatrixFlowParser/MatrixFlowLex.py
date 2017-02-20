#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex

reserved = {
    r'proto$|protocol$|pr$': 'PROTOCOL',
    r'ip-src$|ip-source$|ips$': 'IP_SRC',
    r'ip-dst$|ip-destination$|ipd$': 'IP_DST',
    r'port-src$|port-source$|ps$': 'PORT_SRC',
    r'port-dst$|port-destination$|pd$': 'PORT_DST',
    r'action$': 'ACTION',
}

tokens = [
             'DBL_HYPHEN',
             'COLON',
             'WS',
             'NL',
             'WORD',
] + list(reserved.values())


def t_DBL_HYPHEN(t):
    r'--'
    return t


def t_COLON(t):
    r':'
    return t


def t_WS(t):
    r'[ \t]+'
    pass


def t_NL(t):
    r'[\n\r]+'
    return t


def t_WORD(t):
    r'[a-zA-Z0-9/\\\.,_-]+'
    # Check for reserved words
    for k, v in reserved.items():
        if re.match(k, t.value, re.I):
            t.type = v
    return t


def t_error(t):
    t.lexer.skip(1)
    raise SyntaxError

lexer = lex.lex()

if __name__ == '__main__':
    lex.runmain()
