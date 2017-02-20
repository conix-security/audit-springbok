__author__ = 'maurice'

#!/usr/bin/python

import ply.lex as lex
import re

reserved = {
    r'network_objects$': 'NETOBJ',
    r'type$': 'TYPE',
    r'bogus_ip$': 'BOGUS_IP',
    r'ipaddr_first$': 'IPADDR_FIRST',
    r'ipaddr_last$': 'IPADDR_LAST',
    r'netmask$': 'NETMASK',
    r'ipaddr$': 'IPADDR',
    r'ifindex$': 'IFINDEX',
    r'officialname$': 'OFFICIALNAME',
    r'interfaces$': 'INTERFACES',
    r'ReferenceObject$': 'REFERENCEOBJECT',
    r'netaccess$': 'NETACCESS',
    r'edges$': 'EDGES',
    r'resource$': 'RESOURCE',
    r'policies_collections$' : 'POLICIES_COLLECTIONS',
    r'atlas_general_properties$': 'ATLAS_GENERAL_PROPERTIES',
    r'atlas_gateway_properties$': 'ATLAS_GATEWAY_PROPERTIES',
    r'sofaware_gw_types$': 'SOFAWARE_GW_TYPES',
    r'superanyobj$': 'SUPERANYOBJ',
    r'anyobj$': 'ANYOBJ',
    r'Any$': 'ANY',
    r'overlap_nat_netmask$': 'OVERLAP_NAT_NETMASK',
    r'valid_ipaddr$': 'VALID_IPADDR',
    r'version$': 'VERSION',
    r'versions$': 'VERSIONS',
    r'gx_version$': 'GX_VERSION',
    r'servobj$': 'SERVOBJ',
    r'rules$': 'RULES',
    r'rule$': 'RULE',
    r'rule-base': 'RULEBASE',
    r'action$': 'ACTION',
    r'install$': 'INSTALL',
    r'services$': 'SERVICES',
    r'src$': 'SRC',
    r'dst$': 'DST',
    r'exception$': 'EXCEPTION',
    r'ip_address$': 'IP_ADDRESS',
    r'network_publish_mask$': 'NETWORK_PUBLISH_MASK',
    r'portals$': 'PORTALS',




   # create_version_on_install_policy




}

tokens = [
         #   'PLUS',
           # 'HYPHEN',
            #'SLASH',
            'IP_ADDR',
            'NUMBER',
            'WS',
            'NL',
            'LPAREN',
            'RPAREN',
            'COLON',
            'APOS',
            'LBRACE',
            'RBRACE',
            'WORD',
            'COLONPROTO',
            'COLONPORT',



] + list(reserved.values())

literals = [' ']



t_APOS = r'"'
t_LBRACE = r'\{'
t_RBRACE = r'\}'
t_COLON = r':'
'''
def t_PLUS(t):
    r'\+'
    return t

#def t_HYPHEN(t):
#    r'-'
#    return t

def t_SLASH(t):
    r'/'
    return t
'''
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

def t_LPAREN(t):
    r'\('
    return t

def t_RPAREN(t):
    r'\)'
    return t




def t_WORD(t):
    r'(\"[^\"]+\")|[@a-zA-Z0-9/\\\.,_-]+'
    # Check for reserved words
    for k, v in reserved.items():
        if re.match(k, t.value, re.I):
            t.type = v
    return t


def t_error(t):
    t.lexer.skip(1)
    return t










lexer = lex.lex()