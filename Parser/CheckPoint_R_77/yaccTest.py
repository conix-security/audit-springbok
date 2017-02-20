__author__ = 'maurice'

#/usr/bin/python
# -*- coding: utf-8 -*-


from ply import yacc as yacc

from lexTest import tokens
from lexTest import lexer




object_dict = {}




p_info = {}

def p_lines(p):
    '''lines : line
             | line lines'''
    if len(p) == 2:
        p[0] = p[1]



def p_line(p):
    '''line : obj_line NL
            | NL'''
    p[0] = p[1]


def p_line_error(p):
    '''line : error NL'''

def p_empty(p):
    '''empty :'''
    pass


def p_item(p):
    '''item : WORD
            | NUMBER'''
    p[0] = p[1]


### opt_item
def p_optitem(p):
    '''optitem : item
               | empty'''
    p[0] = p[1]




# parsing objects


def p_obj_line(p):
    '''obj_line : COMA NETOBJ LPAREN NETOBJ'''



def p_obj_line2(p):
    '''obj_line : COMA LPAREN item'''

def p_obj_line3(p):
    '''obj_line : COMA BOGUS_IP LPAREN IP_ADDR RPAREN
                | COMA TYPE LPAREN item RPAREN
                | COMA IPADDR LPAREN IP_ADDR  RPAREN
                | COMA NETMASK LPAREN IP_ADDR  RPAREN
                | COMA IPADDR_FIRST LPAREN IP_ADDR RPAREN
                | COMA IPADDR_LAST LPAREN IP_ADDR RPAREN
                 '''
    print 'trouve'

























def p_error(p):
    if p_info['raise_on_error']:
        if p:
            print("Syntax error at '%s'" % p.value)
        else:
            print("Syntax error at EOF")
        raise SyntaxError


parser = yacc.yacc(optimize=1)

if __name__ == '__main__':
    while True:
        try:
            f = open('objTest')
            s = f.read()
        except EOFError:
            break
        if not s: continue
        result = parser.parse(s + '\n')
        print result
        f.close()
        break
__author__ = 'maurice'
