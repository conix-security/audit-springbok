#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex


######## Modification of the class by Maurice TCHAMGOUE N. on 29-05-2015
###          * Adding the grammar to parse Routes

reserved = {
    r'any|\"any\"$': 'ANY',
    r'set$': 'SET',
    r'unset$': 'UNSET',
    r'policy$': 'POLICY',
    r'global$': 'GLOBAL',
    r'id$': 'ID',
    r'top$': 'TOP',
    r'before$': 'BEFORE',
    r'name$': 'NAME',
    r'from$': 'FROM',
    r'to$': 'TO',
    r'nat$': 'NAT',
    r'src$': 'SRC',
    r'dst$': 'DST',
    r'dip-id$': 'DIP_ID',
    r'ip$': 'IP',
    r'port$': 'PORT',
    r'deny$': 'DENY',
    r'reject$': 'REJECT',
    r'permit$': 'PERMIT',
    r'tunnel$': 'TUNNEL',
    r'l2tp$': 'L2TP',
    r'vpn-group$': 'VPN_GROUP',
    r'vpn$': 'VPN',
    r'pair-policy$': 'PAIR_POLICY',
    r'move$': 'MOVE',
    r'after$': 'AFTER',
    r'default-permit-all$': 'DEFAULT_PERMIT_ALL',
    r'exit$': 'EXIT',
    r'dst-address$': 'DST_ADDRESS',
    r'src-address$': 'SRC_ADDRESS',
    r'negate$': 'NEGATE',
    r'service$': 'SERVICE',
    r'address$': 'ADDRESS',
    r'timeout$': 'TIMEOUT',
    r'session-cache$': 'SESSION_CACHE',
    r'protocol$': 'PROTOCOL',
    r'tcp$': 'TCP',
    r'udp$': 'UDP',
    r'icmp$': 'ICMP',
    r'src-port$': 'SRC_PORT',
    r'dst-port$': 'DST_PORT',
    r'type$': 'TYPE',
    r'code$': 'CODE',
    r'never$': 'NEVER',
    r'group$': 'GROUP',
    r'comment$': 'COMMENT',
    r'add$': 'ADD',
    r'hidden$': 'HIDDEN',
    r'interface$': 'INTERFACE',
    r'secondary$': 'SECONDARY',
    r'zone$': 'ZONE',
    r'tag$': 'TAG',
    r'hostname$': 'HOSTNAME',
    r'disable$': 'DISABLE',
    r'application': 'APPLICATION',
    r'attack': 'ATTACK',
    r'av$': 'AV',
    r'route$':'ROUTE',
    r'gateway$': 'GATEWAY',
    r'preference$': 'PREFERENCE',
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

