__author__ = 'maurice'

#!/usr/bin/python
# coding=utf-8

import ply.yacc as yacc

import ply.lex as lex

from calcLex import tokens

operations = {
    '+' : lambda x, y : x+y,
    '-' : lambda x, y : x-y,
    '/' : lambda x, y : x/y,
    '*' : lambda x, y : x*y,
}



def p_all(p) :
    '''expression : expression PLUS expression
               | expression MINUS expression
               | expression DIVIDE expression
               | expression TIMES expression
               | NUMBER'''
    if len(p) == 2 : p[0] = p[1]
    else : p[0]= operations[p[2]](p[1], p[3])


def p_all3 (p) :
    '''expression : LPAREN expression RPAREN '''
    p[0] = p[2]


def p_error(p):
    print "Syntax error in input!"


def p_expr_uminus (p) :
    '''expression : MINUS expression %prec UMINUS'''
    p[0] = -p[2]

def p_expr_plus (p) :
    '''expression : PLUS expression %prec UMINUS'''
    p[0] = p[2]

precedence = (
    ('left','PLUS', 'MINUS'),
    ('left','TIMES','DIVIDE'),
    ('right', 'UMINUS'),
)
# build the parser

parser = yacc.yacc()

while True :
    try :
        s = raw_input('calc > ')
    except EOFError :
        break
    if not s : continue
    result = parser.parse(s, debug=1)
    print result
