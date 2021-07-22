#!/usr/bin/env python3

import ply.lex as lex

tokens = (
    'SPACE',
    'NUMBER',
    'ADDRESS',
    'COLON',
    'PLUS',
    'LPAREN',
    'RPAREN',
    'MINUS',
    'HASH',
    'COMA',
    'DOT',
    'EQUAL',
    'SANITIZER',
    'FILENAME',
    'ERROR_TYPE',
    'LBRACK',
    'RBRACK',
    'ASCII',
    'TIMES',
    'HINT',
    'NEWLINE',
    'PATH',
    'FUNCTION',
    'SPACES',
    'SANITIZER_DESC',
    'STRING',
    'MSG',
)


def t_FUNCTION(t):
    r'in\ [^\d].*\)\ '
    return t

# single characters
t_COLON = r':'
t_PLUS = r'\+'
t_LPAREN = r'\('
t_RPAREN = r'\)'
t_SPACE = r'\ '
t_NUMBER = r'\d+'
t_MINUS = r'-'
t_HASH = r'\#'
t_COMA = r','
t_DOT = r'\.'
t_EQUAL = r'=+'
t_LBRACK = r'\['
t_RBRACK = r'\]'
t_TIMES = r'\*'

# sinitizer type
t_SANITIZER = r'[A-Za-z]+Sanitizer'
t_SANITIZER_DESC = r'([A-Za-z]+-)+\w+'

# const strings
t_HINT = r'HINT'

t_ADDRESS = r'0x[A-Fa-f0-9]{3,}'
t_FILENAME = r'[\w\-\+\d]+\.[\w]+'
def t_ERROR_TYPE(t):
    r'[A-Za-z]+\ error:\ .*'
    return t


t_ASCII = r'\w+'
t_PATH = r'\.?(\w+)?(/[\w\d\.]+)+/'
t_SPACES = r'\ {2,}'
t_STRING = r'(\".*\")|(\'.*\')'
t_MSG = r'<==\ .*'

def t_NEWLINE(t):
    r'\n+'
    t.lexer.lineno += len(t.value)
    return t

def t_error(t):
    print("Illegal character '%s'" % t.value[0])
    t.lexer.skip(1)

t_ignore = '\t'

lexer = lex.lex()


# if __name__=="__main__":
#     data = '''0x0000801d8e70: 00 00 00 00 00 00 00 00 00 00 f9 f9 f9 f9 f9 f9'''

#     lexer.input(data)

#     while True:
#         tok = lexer.token()
#         if not tok:
#             break
#         print(tok.type, end=' ')