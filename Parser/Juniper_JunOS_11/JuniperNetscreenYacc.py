#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Juniper Netscreen parser.
Each parser construct their firewall as they want,
but they must implement some function :
- init(name, raise_on_error=False)
- update():
- finish():
- get_firewall():
- show():
"""

from Parser.ply import yacc
from Parser.Juniper_JunOS_11.JuniperNetscreenLex import tokens
from Parser.Juniper_JunOS_11.JuniperNetscreenLex import lexer
from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Interface import Interface
from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Firewall import Firewall
from SpringBase.ACL import ACL
from SpringBase.Action import Action
import NetworkGraph
import socket
import re
import JuniperNetscreenPort
import ntpath
from SpringBase.Route import Route
from socket import inet_ntoa
from struct import pack
import copy



parsing_level1 = ''
parsing_level2 = ''
parsing_level3 = ''

networks = []
networks_set = []

services = []
services_set  = []

current_service = {}

current_set = {}

policies = []

cptr = 0

zones = []

current_acl =ACL(None)

current_iface = Interface(None)
current_sub_iface = Interface(None)
ifaces = []

# Use for construct dictionary of object and object group
object_dict = {}



# Use for detect state
p_info = {
    'firewall': Firewall(),
    'current_policy': Rule(0, "", [], [], [], [], [], Action(False)),
    'context_policy': Rule(0, "", [], [], [], [], [], Action(False)),
    'policy_zone_src': None,
    'policy_zone_dst': None,
    'current_object': None,
    'used_object': set(),
    'policy_context': 0,
    'index_rule': -1,
    'default_permit_all': False,
    'raise_on_error': False,
    'route_list': [],
    'current_route' : Route(None, None,None, None,None, 1),
    'index_route': 0,
    'rules' : [],
}


def init(name, raise_on_error=False):
    object_dict.clear()
    p_info['firewall'] = Firewall()
    p_info['firewall'].name = name
    p_info['firewall'].hostname = ntpath.basename(name)
    p_info['firewall'].type = 'Juniper Netscreen'
    p_info['current_policy'] = Rule(0, "", [], [], [], [], [], Action(False))
    p_info['context_policy'] = Rule(0, "", [], [], [], [], [], Action(False)),
    p_info['policy_zone_src'] = None
    p_info['policy_zone_dst'] = None
    p_info['current_object'] = []
    p_info['used_object'] = set()
    p_info['policy_context'] = 0
    p_info['index_rule'] = -1
    p_info['default_permit_all'] = False
    p_info['raise_on_error'] = raise_on_error
    p_info['route_list']= []
    p_info['current_route'] = Route(None, None,None, None,None, 1)
    p_info['index_route'] = 0


def update():
    p_info['current_route'] = Route(None, None,None, None,None, 1)
    p_info['index_route'] = len(p_info['route_list'])
    pass


def finish():
    global ifaces, zones
    p_info['firewall'].interfaces = list(ifaces)
    insert_rules()
    print [a.to_string() for a in p_info['firewall'].interfaces]
    #if p_info['default_permit_all']:
    #    for acl in p_info['firewall'].acl:
    #        acl.rules.append(Rule(-1, 'default', [], [], [], [], [], Action(True)))

def get_firewall():
    firewall = p_info['firewall']
    out_zones = ['ZN_IMN', 'ZN_RAEI', 'ZN_GCN']
    print 'acls---------------------------'
    for acl in p_info['firewall'].acl:
        print acl.name

    return [p_info['firewall']]


def insert_rules():
    global policies, current_acl, zones
    for rule in p_info['rules']:
        rule.ip_dest = resolve_addr(rule.ip_dest)
        rule.ip_source = resolve_addr(rule.ip_source)
        rule.protocol = list(set(resolve_app(rule.port_dest)[0]))
        rule.port_dest = list(set(resolve_app(rule.port_dest)[1]))
        #print rule.to_string()

    ## Bind ACL to ifaces
    for _acl in p_info['firewall'].acl:
        _acl.firewall = p_info['firewall']
        '''print _acl.name
        for r in _acl.rules:
            print r.to_string()'''
        src = _acl.name.split('-')[0]
        dst = _acl.name.split('-')[1]
        for zone in zones:
            if zone['name'] == src:
                src_ifaces = zone['elts']
            if zone['name'] == dst:
                dst_ifaces = zone['elts']
        for src_iface in src_ifaces:
            for dst_iface in dst_ifaces:
                s_iface = p_info['firewall'].get_interface_by_nameif(src_iface)
                d_iface = p_info['firewall'].get_interface_by_nameif(dst_iface)
                print s_iface.to_string()
                print d_iface.to_string()
                NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(_acl,
                                          p_info['firewall'],
                                          p_info['firewall'].get_interface_by_nameif(src_iface),
                                          p_info['firewall'].get_interface_by_nameif(dst_iface))
                        #pass

def resolve_addr(addr_list):
    global networks, networks_set

    res_addr_list = []
    for addr in addr_list:
        if addr == 'any':
            return []
        if addr in [a['name'] for a in networks]:
            for a in networks:
                if a['name'] == addr:
                    res_addr_list.append(a['ip_addr'])
        elif addr in [a['name'] for a in networks_set]:
            for a in networks_set:
                if a['name'] == addr:
                    for b in a['elts']:
                        for c in networks:
                            if c['name'] == b:
                                res_addr_list.append(c['ip_addr'])
    return res_addr_list

def resolve_app(app_list):
    global services, services_set
    protocols, dest_ports, _protocols, _dest_ports = [], [], [], []
    for app in app_list:
        if app == 'any':
            return [], []
        if app in [a['name'] for a in services]:
            fill_service(app, protocols, _protocols, _dest_ports, dest_ports)
        elif app in [a['name'] for a in services_set]:
            fill_service_set(app, protocols, _protocols, _dest_ports, dest_ports)
    return _protocols, _dest_ports




def fill_service(app, protocols, _protocols, _dest_ports, dest_ports):
    for service in services:
        if service['name'] == app:
            if service.has_key('protocol') :
                if service['protocol'] not in protocols:
                    protocols.append(service['protocol'])
                    _protocols.append(Operator('EQ', Protocol(service['protocol'])))
            if service.has_key('port'):
                _dest_ports.append(Operator('EQ', Port(int(service['port']))))
            if service.has_key('lport') and service.has_key('rport'):
                _dest_ports.append(Operator('RANGE', Port(int(service['lport'])), Port(int(service['rport']))))

def fill_service_set(app, protocols, _protocols, _dest_ports, dest_ports):
    for service_set in services_set:
        if service_set['name'] == app:
            elts = service_set['elts']
            for elt in elts:
                if elt in [a['name'] for a in services]:
                    fill_service(elt, protocols, _protocols, _dest_ports, dest_ports)
                elif elt in [a['name'] for a in services_set]:
                    for new_service_set in services_set:
                        if new_service_set['name'] == elt:
                            new_elts = new_service_set['elts']
                            for new_elt in new_elts:
                                if new_elt in [a['name'] for a in services]:
                                    fill_service(new_elt, protocols, _protocols, _dest_ports, dest_ports)



def remove_quote(name):
    if re.match(r'\".*\"', name):
        return name[1:-1]
    return name


precedence = (
    ('left', 'NUMBER'),
)


def fromDotted2Dec(ipaddr):
    return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

def fromDec2Dotted(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))


def p_lines(p):
    '''lines : line
             | line lines'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + '\n' + p[2]





# Usefull expression

def p_line_error(p):
    '''line : error NL'''


def p_empty(p):
    '''empty :'''
    pass


### items
def p_items_1(p):
    '''items : item items'''
    p[0] = p[1] + ' ' + p[2]


def p_items_2(p):
    '''items : item'''
    p[0] = p[1]


def p_item(p):
    '''item : WORD
            | NUMBER'''
    p[0] = p[1]


### words
def p_words_1(p):
    '''words : WORD'''
    p[0] = p[1]


def p_words_2(p):
    '''words : WORD words'''
    p[0] = p[1] + ' ' + p[2]

##################  GRAMMAR  ######################
#####                                         ####

# hostname

### hostname_line
def p_hostname_line(p):
    '''hostname_line : HOST_NAME WORD SEMI_COLON'''
    print p[2]

## useful
def p_level_line(p):
    '''level_line : WORD LBRACKET'''
    global parsing_level1, parsing_level2, parsing_level3, cptr, current_iface,\
        current_set
    cptr += 1
    if p[1] == 'security':
        parsing_level1 = 'security'
    if p[1] == 'address-book':
        parsing_level2 = 'networks'
    if p[1] == 'global':
        parsing_level3 = 'address'
        print '-----------------beginning parsing networks-------------------'
    if p[1] == 'applications':
        parsing_level1 = 'services'
    if p[1] == 'interfaces' and cptr == 1:
        parsing_level2 = 'interfaces'
    if p[1] ==  'interfaces' and parsing_level2 == 'zones':
        parsing_level3 = 'zones_ifaces'
    ### parsing interfaces name
    if cptr == 2 and parsing_level2 == 'interfaces':
        current_iface.nameif = p[1]


    if p[1] == 'zones' and cptr == 2:
        parsing_level2 = 'zones'



    if parsing_level3 == 'zones_ifaces' and cptr == 5:
        if current_set.has_key('elts'):
            current_set['elts'].append(p[1])
        else:
            current_set['elts'] = []
            current_set['elts'].append(p[1])
### Parsing security zones ###

def p_zone_name_line(p):
    '''zone_line : SECURITY_ZONE WORD LBRACKET'''
    global current_set, parsing_level2, parsing_level3, cptr
    cptr += 1
    current_set['name'] = p[2]

def p_zone_iface(p):
    '''zone_line : WORD SEMI_COLON'''
    global zones, current_set, parsing_level2, parsing_level3

    if parsing_level2 == 'zones' and parsing_level3 == 'zones_ifaces' \
            and cptr == 4:
        print 'cptr -- >' + str(cptr)
        print p[1]
        if current_set.has_key('elts'):
            current_set['elts'].append(p[1])
        else:
            current_set['elts'] = []
            current_set['elts'].append(p[1])

#### Parsing ACL

def p_acl_name_line(p):
    '''acl_name_line : FROM_ZONE WORD TO_ZONE WORD LBRACKET'''
    global current_acl, cptr
    cptr += 1
    if current_acl.name != None :
        p_info['firewall'].acl.append(current_acl)
    current_acl = ACL(None)
    current_acl.name = p[2] + '-' + p[4]


def p_address_line(p):
    '''address_line : ADDRESS WORD IP_ADDR SLASH NUMBER SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, networks
    if parsing_level1 == 'security' and parsing_level2 == 'networks' and parsing_level3 == 'address':
        networks.append({'name' : p[2], 'ip_addr' : Ip(p[3], fromDec2Dotted(int(p[5])))})


def p_address_set_line(p):
    '''address_line : ADDRESS_SET WORD LBRACKET'''
    global parsing_level1, parsing_level2, parsing_level3, current_set, cptr
    cptr += 1
    parsing_level3 = 'address_set'
    current_set['name'] = p[2]


def p_address_line2(p):
    '''address_line : ADDRESS WORD SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_set
    if parsing_level3 == 'address_set':
        if 'elts' in current_set.keys():
            current_set['elts'].append(p[2])
        else:
            current_set['elts'] = []
            current_set['elts'].append(p[2])


#### parsing applications

def p_service_name(p):
    '''service_line : APPLICATION WORD LBRACKET'''
    global parsing_level1, parsing_level2, parsing_level3, current_set, current_service, cptr
    cptr += 1
    parsing_level3 = 'service'
    current_service['name'] = p[2]

def p_protocol(p):
    '''service_line : PROTOCOL WORD SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_service
    if parsing_level3 == 'service':
        current_service['protocol'] = p[2]

def p_dest_port(p):
    '''service_line : DEST_PORT NUMBER SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_service
    if parsing_level3 == 'service':
        current_service['port'] = p[2]

def p_dest_port2(p):
    '''service_line : DEST_PORT NUMBER HYPHEN NUMBER SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_set
    if parsing_level3 == 'service':
        current_service['portL'] = p[2]
        current_service['portR'] = p[4]


# in case of icmp, parsing the icmp code
def p_icmp_code(p):
    '''service_line : ICMP_CODE NUMBER SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_set
    if parsing_level3 == 'service':
        current_service['icmp_code'] = p[2]


# parsing application set

def p_service_set_name(p):
    '''service_set_line : APPLICATION_SET WORD LBRACKET'''
    global parsing_level1, parsing_level2, parsing_level3, current_set, cptr
    cptr += 1
    parsing_level3 = 'service_set'
    current_set['name'] = p[2]

def p_service_comp(p):
    '''service_set_line : APPLICATION WORD SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_set
    if parsing_level3 == 'service_set':
        if 'elts' in current_set.keys():
            current_set['elts'].append(p[2])
        else:
            current_set['elts'] = []
            current_set['elts'].append(p[2])
    elif parsing_level3 == 'policy':
        p_info['current_policy'].port_dest.append(p[2])

def p_service_comp2(p):
    '''service_set_line : APPLICATION_SET WORD SEMI_COLON'''
    global parsing_level1, parsing_level2, parsing_level3, current_set
    if parsing_level3 == 'service_set':
        current_set['app_set'] = ''
        if 'elts' in current_set.keys():
            current_set['elts'].append(p[2])
        else:
            current_set['elts'] = []
            current_set['elts'].append(p[2])
    elif parsing_level3 == 'policy':
        p_info['current_policy'].port_dest.append(p[2])
j = 0

def p_end_line(p):
    '''end_line : RBRACKET'''
    global parsing_level1, parsing_level2, parsing_level3, current_set,current_service,\
        networks_set, networks, services, services_set, cptr, j, current_iface, ifaces, zones
    cptr -= 1
    j += 1
    if parsing_level3 == 'address_set':
        networks_set.append({'name' : current_set['name'], 'elts' : list(current_set['elts'])})
        current_set['name'] = ''
        parsing_level3 = ''
        del current_set['elts'][:]
    elif parsing_level3 == 'service':
        services.append(dict(current_service))
        current_service.clear()
        parsing_level3 = ''
    elif parsing_level3 == 'service_set':
        services_set.append({'name' : current_set['name'], 'elts' : list(current_set['elts'])})
        current_set['name'] = ''
        del current_set['elts'][:]
        parsing_level3 = ''
    #print 'cptr ....................' + str(cptr)
    if cptr ==  1 and parsing_level2 == 'interfaces':
        #p_info['firewall'].interfaces.append(current_iface)
        ifaces.append(current_iface)
        current_iface = Interface(None)
    if cptr == 0 and parsing_level2 == 'interfaces':
        parsing_level2 = ''
    if cptr == 2 and parsing_level3 == 'sub_interface':
        parsing_level3 = ''

    ### to parse security zones
    if parsing_level3 == 'zones_ifaces' and cptr == 3:
        zones.append(copy.deepcopy(current_set))
        current_set.clear()
        parsing_level3 = ''
    if cptr == 1 and parsing_level2 == 'zones':
        parsing_level2 = ''


#### parsing interfaces

def p_unit_line(p):
    '''iface_attr_line : UNIT NUMBER LBRACKET'''
    global cptr, current_iface, current_sub_iface, parsing_level3
    cptr += 1
    if cptr == 3 and parsing_level2 == 'interfaces':
        parsing_level3 = 'sub_interface'
        current_sub_iface.nameif = current_iface.nameif + '.' + p[2]

def p_description_line(p):
    '''iface_attr_line : DESCRIPTION WORD SEMI_COLON'''
    global current_sub_iface, cptr, parsing_level3, ifaces
    if parsing_level3 == 'sub_interface':
        current_sub_iface.name = p[2]

def p_sub_iface_address_line(p):
    '''iface_attr_line : ADDRESS IP_ADDR SLASH NUMBER SEMI_COLON
                       | ADDRESS IP_ADDR SLASH NUMBER LBRACKET '''
    global current_sub_iface, cptr, parsing_level3, current_iface
    if p[5] == '{':
        cptr += 1
    if parsing_level3 == 'sub_interface':
        current_sub_iface.network = Ip(p[2], fromDec2Dotted(int(p[4])))
        ifaces.append(current_sub_iface)
        #current_iface.sub_interfaces.append(current_sub_iface)
        #p_info['firewall'].interfaces.append(current_sub_iface)
        del current_sub_iface.sub_interfaces[:]
        current_sub_iface = Interface(None)
        parsing_level3 = ''


### parsing rules

def p_policy_name_line(p):
    '''policy_name_line : POLICY WORD LBRACKET'''
    global parsing_level3, cptr
    cptr += 1
    parsing_level3 = 'policy'
    p_info['current_policy'] = Rule(p[2], p[2], [], [], [], [], [], Action(False))

def p_policy_name_line2(p):
    '''policy_name_line : POLICY NUMBER WORD LBRACKET'''
    global parsing_level3, cptr
    cptr += 1
    parsing_level3 = 'policy'
    p_info['current_policy'] = Rule(p[2] + p[3], p[2] + p[3], [], [], [], [], [], Action(False))

def p_source_address(p):
    '''src_addr_line : SRC_ADDR WORD SEMI_COLON'''
    global parsing_level3
    if parsing_level3 == 'policy':
        p_info['current_policy'].ip_source.append(p[2])

def p_source_address2(p):
    '''src_addr_line : SRC_ADDR LBRACES words RBRACES SEMI_COLON'''
    global parsing_level3
    if parsing_level3 == 'policy':
        tmp_list = p[3].split()
        for addr in tmp_list:
            p_info['current_policy'].ip_source.append(addr)


def p_destination_address(p):
    '''dst_addr_line : DST_ADDR WORD SEMI_COLON'''
    global parsing_level3
    if parsing_level3 == 'policy':
        p_info['current_policy'].ip_dest.append(p[2])

def p_destination_address2(p):
    '''dst_addr_line : DST_ADDR LBRACES words RBRACES SEMI_COLON'''
    global parsing_level3
    if parsing_level3 == 'policy':
        tmp_list = p[3].split()
        for addr in tmp_list:
            p_info['current_policy'].ip_dest.append(addr)


def p_application2(p):
    '''application_line : APPLICATION LBRACES words RBRACES SEMI_COLON'''
    global parsing_level3
    if parsing_level3 == 'policy':
        tmp_list = p[3].split()
        for app in tmp_list:
            p_info['current_policy'].port_dest.append(app)


def p_action_permit(p):
    '''action_line : PERMIT SEMI_COLON'''
    global parsing_level3, current_acl
    if parsing_level3 == 'policy':
        p_info['current_policy'].action = Action(True)
        p_info['rules'].append(p_info['current_policy'])
        current_acl.rules.append(p_info['current_policy'])
        p_info['current_policy'] = Rule(0, "", [], [], [], [], [], Action(False))
        parsing_level3 = ''


def p_action_reject(p):
    '''action_line : REJECT SEMI_COLON'''
    global parsing_level3, current_acl
    if parsing_level3 == 'policy':
        p_info['current_policy'].action = Action(False)
        p_info['rules'].append(p_info['current_policy'])
        current_acl.rules.append(p_info['current_policy'])
        p_info['current_policy'] = Rule(0, "", [], [], [], [], [], Action(False))
        parsing_level3 = ''

def p_action_reject2(p):
    '''action_line : DENY SEMI_COLON'''
    global parsing_level3, current_acl
    if parsing_level3 == 'policy':
        p_info['current_policy'].action = Action(False)
        p_info['rules'].append(p_info['current_policy'])
        current_acl.rules.append(p_info['current_policy'])
        p_info['current_policy'] = Rule(0, "", [], [], [], [], [], Action(False))
        parsing_level3 = ''


### parsings interfaces  ###


def p_error(p):
    if p_info['raise_on_error']:
        if p:
            print("Syntax error at '%s'" % p.value)
        else:
            print("Syntax error at EOF")
        raise SyntaxError



def p_line(p):
    '''line : hostname_line NL
            | words NL
            | address_line NL
            | level_line NL
            | end_line NL
            | service_line NL
            | service_set_line NL
            | policy_name_line NL
            | action_line NL
            | application_line NL
            | dst_addr_line NL
            | src_addr_line NL
            | iface_attr_line NL
            | error_line NL
            | zone_line NL
            | acl_name_line NL
            | NL'''
    p[0] = p[1]
    global cptr
    #print cptr
    #print p[1]


def p_test_error_line(p):
    '''error_line : error LBRACKET
                  | IP_ADDR LBRACKET'''
    global cptr
    cptr += 1




parser = yacc.yacc(optimize=1)

if __name__ == '__main__':
    while True:
        try:
            s = raw_input('JuniperNetscreen > ')
        except EOFError:
            break
        if not s: continue
        print s
        result = parser.parse(s + '\n')
        print result