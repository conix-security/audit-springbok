#!/usr/bin/python

import ply.lex as lex

#token names list

tokens = (
'NUMBER',
'PLUS',
'MINUS',
'TIMES',
'DIVIDE',
'LPAREN',
'RPAREN',
)

# regulars expressions for tokens

t_PLUS = r'\+'
t_TIMES = r'\*'
t_DIVIDE = r'/'
t_MINUS = r'-'
t_LPAREN = r'\('
t_RPAREN = r'\)'

# regulars expressions rules with some actions code


def t_NUMBER(t) :
	r'[0-9]+\.?[0-9]*'
	t.value = float(t.value)
	return t 
	
# Define a rule so we can track line numbers


def t_newline(t) : 
	r'\n+'
	t.lexer.lineno += len(t.value)

# a string containing ignored characters (spaces and tabs)

t_ignore = ' \t'

# Erroro handling rule 
def t_error(t) :
	print "Illegal character '%s' " %t.value[0]
	t.lexer.skip(1)

# BUild the lexer 

lexer = lex.lex()


# Test

data = '''
3 + 4 * 10 
 + -20 *2
'''

#give the lexer some input

lexer.input (data)

# Tokenize

while True :
	tok = lexer.token()
	if not tok : break   # no more input
	print tok.type, tok.lineno, tok.lexpos




