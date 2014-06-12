#! /usr/bin/env python
# -*- coding: utf-8 -*-

import re
from Parser.ply import lex

reserved = {
    r'any$|any4$': 'ANY',
    r'accept$|permit$': 'ACCEPT',
    r'deny$|reject$': 'DENY',
    r'access-group$': 'ACCESS_GROUP',
    r'in$': 'IN',
    r'out$': 'OUT',
    r'access-list$': 'ACCESS_LIST',
    r'extended$': 'EXTENDED',
    r'standard$': 'STANDARD',
    r'none$': 'NONE',
    r'no$': 'NO',
    # protocol
    r'tcp$': 'TCP',
    r'udp$': 'UDP',
    r'tcp-udp$': 'TCP_UDP',
    r'icmp$': 'ICMP',
    r'icmp6$': 'ICMP6',
    # parameters
    r'host$': 'HOST',
    r'hostname$': 'HOSTNAME',
    r'log$': 'LOG',
    r'interval$': 'INTERVAL',
    r'disable$': 'DISABLE',
    r'default$': 'DEFAULT',
    r'inactive$': 'INACTIVE',
    r'time-range$': 'TIME_RANGE',
    r'remark': 'REMARK',
    # object
    r'object$': 'OBJECT',
    r'object-group$': 'OBJECT_GROUP',
    r'user-group$': 'USER_GROUP',
    r'object-group-user$': 'OBJECT_GROUP_USER',
    r'security-group$': 'SECURITY_GROUP',
    r'object-group-security$': 'OBJECT_GROUP_SECURITY',
    r'user$': 'USER',
    r'name$': 'NAME',
    r'rename$': 'RENAME',
    r'tag$': 'TAG',
    r'network$': 'NETWORK',
    r'service$': 'SERVICE',
    r'protocol$': 'PROTOCOL',
    r'icmp-type$': 'ICMP_TYPE',
    r'icmp-object$': 'ICMP_OBJECT',
    r'group-object$': 'GROUP_OBJECT',
    r'network-object$': 'NETWORK_OBJECT',
    r'protocol-object$': 'PROTOCOL_OBJECT',
    r'port-object$': 'PORT_OBJECT',
    r'service-object$': 'SERVICE_OBJECT',
    r'source$': 'SOURCE',
    r'destination$': 'DESTINATION',
    r'security$': 'SECURITY',
    # interface
    r'interface$': 'INTERFACE',
    r'ip$': 'IP',
    r'address$': 'ADDRESS',
    r'redundant$': 'REDUNDANT',
    r'port-channel$': 'PORT_CHANNEL',
    r'standby$': 'STANDBY',
    r'cluster-pool$': 'CLUSTER_POOL',
    r'nameif$': 'NAMEIF',
    # operators
    r'lt$': 'OP_LT',
    r'gt$': 'OP_GT',
    r'eq$': 'OP_EQ',
    r'neq$': 'OP_NEQ',
    r'range$': 'OP_RANGE',
}

tokens = [
             'BANG',
             'IP_ADDR',
             'NUMBER',
             'WS',
             'NL',
             'WORD',
         ] + list(reserved.values())


def t_ignore_OTHER(t):
    r'^(PIX|enable|passwd|domain-name|logging|mtu|failover|pdm|arp|aaa|timeout|snmp|floodguard|telnet|ssh|console|terminal|crypto|pager|global|nat|static|fixup|route|vpngroup).*$'
    pass


def t_BANG(t):
    r'!'
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
    r'[a-zA-Z0-9/\\\.,_-]+'
    # Check for reserved words
    for k, v in reserved.items():
        if re.match(k, t.value, re.I):
            t.type = v
    return t


def t_error(t):
    print("Illegal character %s" % repr(t.value[0]))
    t.lexer.skip(1)


lexer = lex.lex()

if __name__ == '__main__':
    lex.runmain()
