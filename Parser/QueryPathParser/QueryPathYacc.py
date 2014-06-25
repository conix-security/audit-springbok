#! /usr/bin/env python
# -*- coding: utf-8 -*-

from Parser.ply import yacc
from Parser.QueryPathParser.QueryPathLex import tokens
from Parser.QueryPathParser.QueryPathLex import lexer
from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Protocol import Protocol
from SpringBase.Ip import Ip
from SpringBase.Port import Port
from SpringBase.Action import Action


p_info = {
    'rule_list': [],
    'current_rule': Rule(0, '', [], [], [], [], [], Action(True)),
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
            | NL'''


def p_line_error(p):
    '''line : error NL'''


def p_hyphen_line(p):
    '''hyphen_line : DBL_HYPHEN'''
    p_info['rule_list'].append(p_info['current_rule'])
    p_info['current_rule'] = Rule(0, '', [], [], [], [], [], True)


def p_protocol_line(p):
    '''protocol_line : PROTOCOL COLON WORD'''
    p_info['current_rule'].protocol.append(Operator('EQ', Protocol(p[3])))


def p_ip_src_line_1(p):
    '''ip_src_line : IP_SRC COLON WORD WORD'''
    p_info['current_rule'].ip_source.append(Operator('EQ', Ip(p[3], p[4])))


def p_ip_src_line_2(p):
    '''ip_src_line : IP_SRC COLON WORD'''
    p_info['current_rule'].ip_source.append(Operator('EQ', Ip(p[3])))


def p_ip_dst_line_1(p):
    '''ip_dst_line : IP_DST COLON WORD WORD'''
    p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(p[3], p[4])))


def p_ip_dst_line_2(p):
    '''ip_dst_line : IP_DST COLON WORD'''
    p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(p[3])))


def p_port_src_line(p):
    '''port_src_line : PORT_SRC COLON WORD'''
    p_info['current_rule'].port_source.append(Operator('EQ', Port(p[3])))


def p_port_dst_line(p):
    '''port_dst_line : PORT_DST COLON WORD'''
    p_info['current_rule'].port_dest.append(Operator('EQ', Port(p[3])))


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
        print s
        result = parser.parse(s + '\n')
        print result