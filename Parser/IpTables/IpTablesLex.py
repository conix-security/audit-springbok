#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex

reserved = {
    r'link$': 'LINK',
    r'inet$': 'INET',
    r'addr$': 'ADDR',
    r'Bcast$': 'BCAST',
    r'Mask$': 'MASK',
    r'iptables$': 'IPTABLES',
    r'filter$': 'FILTER',
    r'nat$': 'NAT',
    r'mangle$': 'MANGLE',
    r'raw$': 'RAW',
    r'security$': 'SECURITY',
    r'-t$|--table$': 'TABLE',
    r'-A$|--append$': 'APPEND',
    r'-C$|--check$': 'CHECK',
    r'-D$|--delete$': 'DELETE',
    r'-I$|--insert$': 'INSERT',
    r'-R$|--replace$': 'REPLACE',
    r'-L$|--list$': 'LIST',
    r'-S$|--list-rules$': 'LIST_RULES',
    r'-F$|--flush$': 'FLUSH',
    r'-Z$|--zero$': 'ZERO',
    r'-N$|--new-chain$': 'NEW_CHAIN',
    r'-X$|--delete-chain$': 'DELETE_CHAIN',
    r'-P$|--policy$': 'POLICY',
    r'-E$|--rename-chain$': 'RENAME_CHAIN',
    r'-4$|--ipv4$': 'IPV4',
    r'-6$|--ipv6$': 'IPV6',
    r'-p$|--protocol$': 'PROTOCOL',
    r'-s$|--source$|--src$': 'IP_SOURCE',
    r'-d$|--destination$|--dst$': 'IP_DESTINATION',
    r'-m$|--match$': 'MATCH',
    r'-j$|--jump$': 'JUMP',
    r'-g$|--goto$': 'GOTO',
    r'-i$|--in-interface$': 'IN_INTERFACE',
    r'-o$|--out-interface$': 'OUT_INTERFACE',
    r'--source-port$|--sport$': 'PORT_SOURCE',
    r'--destination-port$|--dport$': 'PORT_DESTINATION',
    r'--state$': 'STATE',
    r'accept$': 'ACCEPT',
    r'reject$|drop$': 'DROP',
    r'queue$': 'QUEUE',
    r'return$': 'RETURN',
    r'via$': 'VIA',
    r'default$': 'DEFAULT',
    r'dev$': 'DEV',
    r'src$': 'SRC',

}

tokens = [
             'BANG',
             'COLON',
             'COMMA',
             'SLASH',
             'EQ',
             'STAR',
             'SQUARE_BRACKET',
             'IP_ADDR',
             'NUMBER',
             'WS',
             'NL',
             'WORD',
         ] + list(reserved.values())


def t_BANG(t):
    r'!'
    return t


def t_COLON(t):
    r':'
    return t


def t_COMMA(t):
    r','
    return t


def t_SLASH(t):
    r'/'
    return t


def t_EQ(t):
    r'='
    return t


def t_STAR(t):
    r'\*'
    return t


def t_SQUARE_BRACKET(t):
    r'\[|\]'
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
    r'(\"[^\"]+\")|[a-zA-Z0-9/\\\.,\$_-]+'
    # Check for reserved words
    for k, v in reserved.items():
        # take case care if k is an option
        if re.match(k, t.value, 0 if k.startswith('-') else re.I):
            t.type = v
    return t


def t_error(t):
    t.lexer.skip(1)
    return t


lexer = lex.lex()

if __name__ == '__main__':
    lex.runmain()
