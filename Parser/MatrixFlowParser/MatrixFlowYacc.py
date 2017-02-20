#! /usr/bin/env python
# -*- coding: utf-8 -*-

from Parser.ply import yacc
from Parser.MatrixFlowParser.MatrixFlowLex import tokens
from Parser.MatrixFlowParser.MatrixFlowLex import lexer
from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Protocol import Protocol
from SpringBase.Ip import Ip
from SpringBase.Port import Port
from SpringBase.Action import Action
import socket
import re
import ntpath
from socket import inet_ntoa
from struct import pack
import copy

def fromDotted2Dec(ipaddr):
    return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

def fromDec2Dotted(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))
p_info = {
    'rule_list': [],
    'current_rule': Rule(0, '', [], [], [], [], [], Action(True)),
    'current_list' : [],
}


def init():
    p_info['rule_list'] = []
    p_info['current_rule'] = Rule(0, '', [], [], [], [], [], Action(True))


def get_query():
    p_info['rule_list'].append(p_info['current_rule'])
    return p_info['rule_list']


def p_lines(p):
    '''lines : line
             | line lines'''


def p_line(p):
    '''line : hyphen_line NL
            | protocol_line NL
            | ip_src_line NL
            | ip_dst_line NL
            | port_src_line NL
            | port_dst_line NL
            | action_line NL
            | NL'''


### words
def p_words_1(p):
    '''words : WORD'''
    p[0] = p[1]



def p_words_2(p):
    '''words : WORD words'''
    p[0] = p[1] + p[2]
    #p_info['current_list'].append(p[1])


def p_line_error(p):
    '''line : error NL'''


def p_hyphen_line(p):
    '''hyphen_line : DBL_HYPHEN'''
    p_info['rule_list'].append(p_info['current_rule'])
    p_info['current_rule'] = Rule(0, '', [], [], [], [], [], Action(False))


def p_protocol_line(p):
    '''protocol_line : PROTOCOL COLON words'''
    for proto in p[3].split(','):
        p_info['current_rule'].protocol.append(Operator('EQ', Protocol(proto)))

def p_protocol_line2(p):
    '''protocol_line : PROTOCOL COLON'''
    pass


def p_ip_src_line_1(p):
    '''ip_src_line : IP_SRC COLON words'''
    for src_ip in p[3].split(','):
        p_info['current_rule'].ip_source.append(Operator('EQ', Ip(src_ip.split('/')[0], fromDec2Dotted(int(src_ip.split('/')[1])))))

def p_ip_src_line_3(p):
    '''ip_src_line : IP_SRC COLON'''
    pass


def p_ip_dst_line_1(p):
    '''ip_dst_line : IP_DST COLON words'''
    for dst_ip in p[3].split(','):
        p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(dst_ip.split('/')[0], fromDec2Dotted(int(dst_ip.split('/')[1])))))


def p_ip_dst_line_3(p):
    '''ip_dst_line : IP_DST COLON'''
    pass


def p_port_src_line(p):
    '''port_src_line : PORT_SRC COLON words'''
    for port_src in p[3].split(','):
        if '-' in port_src:
            p_info['current_rule'].port_source.append(Operator('RANGE', Port(int(port_src.split('-')[0]), Port(int(port_src.split('-')[1])))))
        else:
            p_info['current_rule'].port_source.append(Operator('EQ', Port(int(port_src))))


def p_port_src_line2(p):
    '''port_src_line : PORT_SRC COLON'''
    pass


def p_port_dst_line(p):
    '''port_dst_line : PORT_DST COLON words'''
    for port_dst in p[3].split(','):
        if '-' in port_dst:
            p_info['current_rule'].port_dest.append(Operator('RANGE', Port(int(port_dst.split('-')[0])), Port(int(port_dst.split('-')[1]))))
        else:
            p_info['current_rule'].port_dest.append(Operator('EQ', Port(int(port_dst))))


def p_port_dst_line2(p):
    '''port_dst_line : PORT_DST COLON'''
    pass


def p_action_line(p):
    '''action_line : ACTION COLON WORD'''
    if p[3] == 'accept':
        p_info['current_rule'].action = Action(True)
    else:
        p_info['current_rule'].action = Action(False)


def p_error(p):
    raise SyntaxError

parser = yacc.yacc(optimize=1)

if __name__ == '__main__':
    while True:
        try:
            s = raw_input('QueryPath > ')
        except EOFError:
            break
        if not s: continue
        #print s
        #result = parser.parse(s + '\n')
        #print result