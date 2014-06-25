#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex

reserved = {
    r'config$': 'CONFIG',
    r'firewall$': 'FIREWALL',
    r'hostname$': 'HOSTNAME',
    r'edit$': 'EDIT',
    r'set$': 'SET',
    r'end$': 'END',
    r'next$': 'NEXT',
    r'policy$|policy6$|policy46$|policy64$': 'POLICY',
    r'action$': 'ACTION',
    r'accept$': 'ACCEPT',
    r'deny$': 'DENY',
    r'dstaddr$': 'DST_ADDR',
    r'label$': 'LABEL',
    r'service$': 'SERVICE',
    r'srcaddr$': 'SRC_ADDR',
    r'srcintf$': 'SRC_INTF',
    r'dstintf$': 'DST_INTF',
    r'status$': 'STATUS',
    r'disable$': 'DISABLE',
    r'address$': 'ADDRESS',
    r'end-ip$': 'END_IP',
    r'fqdn$': 'FQDN',
    r'start-ip$': 'START_IP',
    r'subnet$': 'SUBNET',
    r'addrgrp$|addrgrp6$': 'ADDRGRP',
    r'member$': 'MEMBER',
    r'custom$': 'CUSTOM',
    r'protocol$': 'PROTOCOL',
    r'ip$': 'IP',
    r'iprange$': 'IPRANGE',
    r'group$': 'GROUP',
    r'system$': 'SYSTEM',
    r'protocol-number$': 'PROTOCOL_NUMBER',
    r'sctp-portrange$': 'SCTP_PORTRANGE',
    r'tcp-portrange$': 'TCP_PORTRANGE',
    r'udp-portrange$': 'UDP_PORTRANGE',
    r'end-port$': 'END_PORT',
    r'start-port$': 'START_PORT',
    r'interface$': 'INTERFACE',
    r'alias$': 'ALIAS',
    r'global$': 'GLOBAL',
    r'vdom$': 'VDOM',
}

tokens = [
             'MINUS',
             'COLON',
             'SLASH',
             'IP_ADDR',
             'NUMBER',
             'WS',
             'NL',
             'WORD',
         ] + list(reserved.values())


def t_MINUS(t):
    r'-'
    return t


def t_COLON(t):
    r':'
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

