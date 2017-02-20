#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""CheckPoint parser.
Each parser construct their firewall as they want,
but they must implement some function :
- init(name, raise_on_error=False)
- update():
- finish():
- get_firewall():
- show():
"""

from Parser.ply import yacc
from Parser.CheckPoint.CheckPointLex import tokens
from Parser.CheckPoint.CheckPointLex import lexer
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
import re
import ntpath
import socket
from SpringBase.Route import Route
from socket import *
from socket import inet_ntoa
from struct import pack


# Use for detect state
p_info = {
    'firewall_list': [],
    'firewall': Firewall(),
    'interface_state': False,
    'current_interface': None,
    'object_name': None,
    'used_object': set(),
    'bounded_rules': set(),
    'rule_id': 0,
    'rule_list': [],
    'current_rule': Rule(None, None, [], [], [], [], [], Action(False)),
    'index_rule': 0,
    'global_rules': [],
    'raise_on_error': False,
    'route_list': [],
    'current_route' : Route(None, None,None, None,None, 1),
    'index_route': 0
}

# Counters
i, j , k, z, cptr = 0, 0, 0, 0, 0


object_dict = []
used_objects = []
unused_objects = []
current_obj = {}
current_iface = {}
current_ifaces = []
firewalls = []
current_fw = {}
types = set()
hosts = []
networks = []
parsing_object_type = ""
parsing_exception = False
rule_attr = ""
parsing_group_attr = False

members = []
parsing_interfaces = False
parsing_a_rule = False
parsing_rule_arg = False


parsing_rules = False
rules = []
current_rule = {'name': None, 'action': None, 'src': [], 'dst': [], 'install': [], 'services': []}
services = {'udp', 'UDP', 'Udp', 'tcp', 'Tcp', 'TCP', 'other', 'Other','icmp', 'Icmp', 'igmp', 'Igmp',
                                       'Gre', 'gre', 'GRE', 'ospf', 'OSPF', 'Ospf', 'Rpc', 'rpc'}
current_host = {'type': None, 'name' : None, 'ipaddr': None}
d = {'host': list(), 'port': list(), 'protocol': list(), 'machines_range': list(), 'netobj': list()}
nd = {'host': list(), 'port': list(), 'protocol': list(), 'machines_range': list(), 'netobj': list()}

############################# Usefull functions ########################################


##### This function is used to initialised some parameters

def init(name, raise_on_error=False):
    global i, j, k, cptr, current_rule, d, nd
    i, j , k, cptr = 0, 0, 0, 0
    current_rule = {'name': None, 'action': None, 'src': [], 'dst': [], 'install': [], 'services': []}
    p_info['firewall_list'] = []
    p_info['name'] = name
    p_info['hostname'] = ntpath.basename(name)
    p_info['current_rule'] = Rule(None, None, [], [], [], [], [], Action(False))
    p_info['firewall'] = Firewall()
    del object_dict[:], firewalls[:], used_objects[:], rules[:]
    d = {'host': list(), 'port': list(), 'protocol': list(), 'machines_range': list(), 'netobj': list()}
    nd = {'host': list(), 'port': list(), 'protocol': list(), 'machines_range': list(), 'netobj': list()}


#### The update() function is called every time a line is parsed

def update():
    global j
    j += 1


## this method fills the source IP section of all the parsed rules
def finish_src(s):
    tmpObj = resolve(s)
    if tmpObj['type'] in {'host', 'gateway', 'gateway_cluster'}:
        p_info['current_rule'].ip_source.append(Operator('EQ', Ip(tmpObj['ipaddr'])))
    elif tmpObj['type'] == 'network':
        p_info['current_rule'].ip_source.append(Operator('EQ', Ip(tmpObj['ipaddr'], tmpObj['netmask'])))
    elif tmpObj['type'] == 'machines_range':
        p_info['current_rule'].ip_source.append(Operator('RANGE', Ip(tmpObj['start_range']),
                                                         Ip(tmpObj['stop_range'])))
    elif tmpObj['type'] in {'group', 'Group'}:
        for member in tmpObj['members']:
            subTmpOBj = resolve(member)
            if subTmpOBj['type'] in {'host', 'gateway', 'gateway_cluster'}:
                p_info['current_rule'].ip_source.append(Operator('EQ', Ip(subTmpOBj['ipaddr'])))
            elif subTmpOBj['type'] == 'network':
                p_info['current_rule'].ip_source.append(Operator('EQ', Ip(subTmpOBj['ipaddr'],
                                                                          subTmpOBj['netmask'])))
            elif subTmpOBj['type'] == 'machines_range':
                p_info['current_rule'].ip_source.append(Operator('RANGE', Ip(subTmpOBj['start_range']),
                                                                 Ip(subTmpOBj['stop_range'])))

## this method fills the destination IP section of all the parsed rules
def finish_dst(s):
    tmpObj = resolve(s)
    if tmpObj['type'] in {'host', 'gateway', 'gateway_cluster'}:
        p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(tmpObj['ipaddr'])))
    elif tmpObj['type'] == 'network':
        p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(tmpObj['ipaddr'], tmpObj['netmask'])))
    elif tmpObj['type'] == 'machines_range':
        p_info['current_rule'].ip_dest.append(Operator('RANGE', Ip(tmpObj['start_range']),
                                                       Ip(tmpObj['stop_range'])))
    elif tmpObj['type'] in {'group', 'Group'}:
        for member in tmpObj['members']:
            subTmpOBj = resolve(member)
            if subTmpOBj['type'] in {'host', 'gateway', 'gateway_cluster'}:
                p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(subTmpOBj['ipaddr'])))
            elif subTmpOBj['type'] == 'network':
                p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(subTmpOBj['ipaddr'],
                                                                        subTmpOBj['netmask'])))
            elif subTmpOBj['type'] == 'machines_range':
                p_info['current_rule'].ip_dest.append(Operator('RANGE', Ip(subTmpOBj['start_range']),
                                                               Ip(subTmpOBj['stop_range'])))

## this method fills the services (port, protocol) sections of all the parsed rules
def finish_serv(s):
    tmpObj = resolve(s)
    if tmpObj['type'] in {'udp', 'UDP', 'Udp', 'tcp', 'Tcp', 'TCP', 'icmp', 'Icmp', 'igmp', 'Igmp',
                           'Gre', 'gre', 'GRE', 'ospf', 'OSPF', 'Ospf'}:
        p_info['current_rule'].protocol.append(Operator('EQ', Protocol(tmpObj['type'].lower())))
        if tmpObj.has_key('port') :
            p_info['current_rule'].port_dest.append(Operator('EQ', Port(tmpObj['port'])))
        elif tmpObj.has_key('portL'):
            if tmpObj['portR'] == 'infinite':
                p_info['current_rule'].port_dest.append(Operator('GT', Port(tmpObj['portL'])))
            else:
                p_info['current_rule'].port_dest.append(Operator('RANGE', Port(tmpObj['portL']),
                                                                 Port(tmpObj['portR'])))
    elif tmpObj['type'] in {'group', 'Group'}:
        for member in tmpObj['members']:
            subTmpOBj = resolve(member)
            if subTmpOBj['type'] in {'udp', 'UDP', 'Udp', 'tcp', 'Tcp', 'TCP', 'icmp', 'Icmp',
                                     'igmp', 'Igmp', 'Gre', 'gre', 'GRE', 'ospf', 'OSPF', 'Ospf'}:
                p_info['current_rule'].protocol.append(Operator('EQ', Protocol(subTmpOBj['type'].lower())))
            if subTmpOBj.has_key('port') :
                p_info['current_rule'].port_dest.append(Operator('EQ', Port(subTmpOBj['port'])))
            elif subTmpOBj.has_key('portL'):
                p_info['current_rule'].port_dest.append(Operator('RANGE', Port(subTmpOBj['portL']),
                                                                 Port(subTmpOBj['portR'])))
    elif tmpObj['type'] in {'other', 'Other'}:
        p_info['current_rule'].protocol.append(Operator('EQ', Protocol(tmpObj['protocol'])))
    elif tmpObj['type'] in {'Rpc', 'rpc'}:
        p_info['current_rule'].port_dest.append(Operator('EQ', Port(tmpObj['port'])))

## this method is used to build parsed firewall by adding used and unused
#  objects, acls, interfaces...
def finish_fw(acls):
    for fw in firewalls:
        p_info['firewall'] = Firewall()
        p_info['firewall'].name = p_info['name']
        p_info['firewall'].hostname = fw['name']
        p_info['firewall'].type = 'CheckPoint'
        p_info['firewall'].unused_objects = set(unused_objects)
        p_info['firewall'].dictionnary = dict(nd)
        if fw['ifaces']:
            for iface in fw['ifaces']:
                p_info['firewall'].interfaces.append(Interface(iface['name'], Ip(iface['ipaddr'], iface['netmask']),
                                                               iface['index']))

        for name, acl in acls.iteritems():
            if name == p_info['firewall'].hostname:
                newAcl = ACL(name)
                newAcl.rules = acl
                p_info['firewall'].acl.append(newAcl)
                #for interface in p_info['firewall'].interfaces:
                #    NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(newAcl, p_info['firewall'], interface, p_info['firewall'])
                #    NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(newAcl, p_info['firewall'], p_info['firewall'], interface)
        p_info['firewall_list'].append(p_info['firewall'])

# to fill the dictionary of network objects
def fill_obj_dict_netobj(obj):
    if nd.has_key(obj['name']):
        nd[obj['name']].append({obj['name']: Operator('EQ', Ip(obj['ipaddr']))})
    else:
        nd[obj['name']] = list()
        nd[obj['name']].append({obj['name']: Operator('EQ', Ip(obj['ipaddr']))})

# to fill the dictionnary of services objects (port)
def fill_obj_dict_serv1(obj):
    if nd.has_key(obj['name']):
        if obj.has_key('portL'):
            nd[obj['name']].append({obj['name']: Operator('RANGE', Port(obj['portL']), Port(obj['portR']))})
        elif obj.has_key('port'):
            nd[obj['name']].append({obj['name']: Operator('EQ', Port(obj['port']))})
    else:
        nd[obj['name']] = list()
        if obj.has_key('portL'):
            if obj['portR'] == 'infinite':
                nd[obj['name']].append({obj['name']: Operator('GT', Port(obj['portL']))})
            else:
                nd[obj['name']].append({obj['name']: Operator('RANGE', Port(obj['portL']), Port(obj['portR']))})
        elif obj.has_key('port'):
            nd[obj['name']].append({obj['name']: Operator('EQ', Port(obj['port']))})
        else: pass#print obj ????????????????????????????????

# to fill the dictionnary of protocol (part 1)
def fill_obj_dict_serv2(obj):
    if nd.has_key(obj['name']):
        nd[obj['name']].append({obj['name']: Operator('EQ', Protocol(obj['protocol']))})
    else:
        nd[obj['name']] = list()
        nd[obj['name']].append({obj['name']: Operator('EQ', Protocol(obj['protocol']))})

# to fill the dictionnary of protocol (part 1)
def fill_obj_dict_serv3(obj):
    if nd.has_key(obj['name']):
        nd[obj['name']].append({obj['name']: Operator('EQ', Protocol(obj['type'].lower()))})
    else:
        nd[obj['name']] = list()
        nd[obj['name']].append({obj['name']: Operator('EQ', Protocol(obj['type'].lower()))})

# to fill the dictionnary of unused objects
def fill_unused_obj():
     for obj in object_dict:
        if obj['name'] not in p_info['used_object']:
            unused_objects.append(obj['name'])


#### The finish() function is used to construct rules, bind them
#    to different ACLs, then add ACLs to firewalls.

def finish():
    acls = {}
    index = 0
    for fw in firewalls:
        acls[fw['name']] = []
    for rule in rules:
        p_info['current_rule'] = Rule(None, None, [], [], [], [], [], Action(False))
        p_info['current_rule'].identifier = index
        index += 1
        if rule['action'] == 'accept':
            p_info['current_rule'].action = Action(True)
        elif rule['action'] == 'drop':
            p_info['current_rule'].action = Action(False)
        p_info['current_rule'].name = rule['name'] if rule['name'] else 'Rule' + str(index)
        if rule['src']:
            for s in rule['src']:
                finish_src(s)
            for s in rule['dst']:
                finish_dst(s)
            for s in rule['services']:
                finish_serv(s)

        if len(rule['install']) > 0:
            for elt in rule['install']:
                if elt == 'Gateways':
                    for k in acls.keys():
                        acls[k].append(p_info['current_rule'])
                elif acls.has_key(elt):
                    acls[elt].append(p_info['current_rule'])

    fill_unused_obj()
    for obj in object_dict:
        if obj['type'] in {'host', 'gateway', 'gateway_cluster', 'network', 'dynamic_net_obj'} and obj.has_key('ipaddr'):
            fill_obj_dict_netobj(obj)
        elif obj['type'] in {'udp', 'UDP', 'Udp', 'tcp', 'Tcp', 'TCP'} :
            fill_obj_dict_serv1(obj)
        elif obj['type'] in {'other', 'Other'} :
            if obj.has_key('protocol'):
                fill_obj_dict_serv2(obj)
        elif obj['type'] in {'icmp', 'Icmp', 'igmp', 'Igmp',
                                           'Gre', 'gre', 'GRE', 'ospf', 'OSPF', 'Ospf'} :
            fill_obj_dict_serv3(obj)
    finish_fw(acls)
    del firewalls[:]

#### This function is used to return parsed firewalls to the parser.

def get_firewall():

    return (fw for fw in p_info['firewall_list'])

#### The resolve() function is used to resolve an object name
#    with its corresponding value depending of its type.

def resolve(name):
    found = False
    for obj in object_dict:
        if name in obj.values():
            p_info['used_object'].add(name)
            return obj
    if found == False :
        print name, 'Object not found !!!'
        raise SyntaxError

#### Just to retrieve a Firewall object by the name of it.

def get_fw_by_name(name):
    for fw in p_info['firewall_list']:
        if fw['name'] == name: return fw

#### The following two functions are used to convert an IP address from it
#    dotted format to the decimal one and vice-versa

def fromDotted2Dec(ipaddr):
    return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

def fromDec2Dotted(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))


##################### Paser begin here ###################################

##### Usefull expressions

def p_lines(p):
    '''lines : line
             | lines line'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        try:
            p[0] = p[1] + '\n' + p[2]
        except TypeError:
            pass

### this represent different kind of lines that will be usefull for
#   our parser to grab informations about objects and rules

def p_line (p) :
    '''line : begin_line NL
            | begin_net_obj NL
            | obj_name_line NL
            | ipaddr_line NL
            | type_line NL
            | netmask_line NL
            | start_range NL
            | stop_range NL
            | interface_index NL
            | interface_nameif NL
            | interface_begin_line NL
            | end_obj_line NL
            | sub_obj_attr NL
            | attr_line NL
            | usefull_line NL
            | bogus_ip_line NL
            | service_port NL
            | servobj_begin_line NL
            | begin_rules_line NL
            | begin_dst NL
            | begin_action NL
            | begin_src NL
            | begin_install NL
            | exception_line NL
            | ref_object_begin NL
            | new_rule_line NL
            | NL'''
    update()
    p[0] = p[1]
    global z
    #z += 1


def p_line_error(p):
    '''line : error NL'''


def p_empty(p):
    '''empty :'''
    pass


def p_item(p):
    '''item : WORD
            '''
    p[0] = p[1]


### opt_item
def p_optitem(p):
    '''optitem : item
               | empty'''
    p[0] = p[1]


### words : this is intend to be a wilcard to match any word except tokens
# defined in the lexer file

def p_words_1(p):
    '''words : WORD'''
    p[0] = p[1]


def p_words_2(p):
    '''words : WORD words'''
    try:
        p[0] = p[1] + ' ' + p[2]
    except TypeError :
        pass

### This is usefull to maintain the state of the counter. It
#   represent the different ways a new object is declared.
def p_usefull(p):
    '''usefull_line : COLON ANYOBJ LPAREN  ANY
                    | COLON SUPERANYOBJ LPAREN
                    | COLON SOFAWARE_GW_TYPES LPAREN
                    | COLON ATLAS_GATEWAY_PROPERTIES LPAREN
                    | COLON ATLAS_GENERAL_PROPERTIES LPAREN
                    | COLON POLICIES_COLLECTIONS LPAREN
                    | COLON WORD LPAREN SOFAWARE_GW_TYPES RPAREN'''
    global cptr
    cptr += 1

### This line reprensent the beginning of the different sections (objects and rules)

def p_begin_line(p) :
    '''begin_line : LPAREN'''
    global cptr
    cptr += 1


### This line means that we are about to parse network objects(hosts,
#   machines_range, network, firewalls...

def p_begin_net_obj(p):
    '''begin_net_obj : COLON NETOBJ LPAREN'''
    global cptr, parsing_object_type
    parsing_object_type = "networks"
    #print 'begining of parsing...', parsing_object_type
    cptr += 1

### Parsing the object name

def p_obj_name_line(p):
    '''obj_name_line : COLON LPAREN WORD'''
    global cptr, current_obj
    if cptr == 2 :
        current_obj['name'] = p[3]
    cptr += 1
    #check if it is a sub object(sub attr) before assigning the name

def p_obj_name_line1(p):
    '''obj_name_line : COLON LPAREN NUMBER WORD'''
    global cptr, current_obj
    if cptr == 2 :
        current_obj['name'] = p[3] + p[4]
    cptr += 1


### Parsing the object IP address

def p_ipaddr_line(p):
    '''ipaddr_line : COLON IPADDR LPAREN IP_ADDR RPAREN'''
    global cptr, current_obj, current_iface
    if cptr == 3 :
        current_obj['ipaddr'] = p[4]
    elif cptr == 5:
        current_iface['ipaddr'] = p[4]
    # if cptr == 5 : interface

def p_bogus_ip_line(p):
    '''bogus_ip_line : COLON BOGUS_IP LPAREN IP_ADDR RPAREN'''
    global cptr, current_obj
    if cptr == 3:
        current_obj['ipaddr'] = p[4]

### Parsing the object type. The type depends on the state of the counter

def p_type_line(p):
    '''type_line : COLON TYPE LPAREN WORD RPAREN'''
    global cptr, current_obj, current_iface, parsing_group_attr, parsing_object_type, \
        current_rule, parsing_exception, members
    if cptr == 3 :
        current_obj['type'] = p[4]
        if current_obj['type'] in {'group', 'Group'} and parsing_object_type in {'services', 'networks'}:
            current_obj['members'] = list(members)
            members = []
        if current_obj['type'] == 'group_with_exclusion' and parsing_exception == True:
            parsing_exception = False
            #print 'end of parsing...exception'

    elif cptr == 5:
        if p[4] in {'drop', 'accept'} and rule_attr == 'action':
            current_rule['action'] = p[4]
        else: current_iface['type'] = p[4]

### Parsing the netmask

def p_netmask_line(p):
    '''netmask_line : COLON NETMASK LPAREN IP_ADDR RPAREN'''
    global cptr, current_obj
    if cptr == 3 :
        current_obj['netmask'] = p[4]
    elif cptr == 5:
        current_iface['netmask'] = p[4]


### for machines ranges

def p_start_range(p):
    '''start_range : COLON IPADDR_FIRST LPAREN IP_ADDR RPAREN'''
    global cptr, current_obj
    if cptr == 3 :
        current_obj['start_range'] = p[4]


def p_stop_range(p):
    '''stop_range : COLON IPADDR_LAST LPAREN IP_ADDR RPAREN'''
    global cptr, current_obj
    if cptr == 3 :
        current_obj['stop_range'] = p[4]

#### Parsing Interfaces ####

### To detect the begining of an interface object. It also means that
#   the object we are parsing is a gateway.

def p_interface_begin(p):
    '''interface_begin_line : COLON INTERFACES LPAREN'''
    global cptr, current_obj, current_fw, current_iface, parsing_interfaces
    if cptr == 3 :
        parsing_interfaces = True
    current_fw['name'] = current_obj['name']
    cptr += 1


### Parsing the identifier of the interface

def p_interface_index(p):
    '''interface_index : COLON IFINDEX LPAREN NUMBER RPAREN'''
    current_iface['index'] = p[4]

### Parsing the interface name

def p_interface_nameif(p):
    '''interface_nameif : COLON OFFICIALNAME LPAREN WORD RPAREN'''
    global current_iface
    current_iface['name'] = p[4]



#### This line means that we are about to parse services objects (ports, protocols...)

def p_begin_servboj(p):
    '''servobj_begin_line : COLON SERVICES LPAREN'''
    global cptr, parsing_object_type, rule_attr
    if cptr == 1:
        parsing_object_type = "services"
    #print 'begining of parsing...', parsing_object_type
    if cptr == 3 and parsing_object_type == 'rules':
        rule_attr = "services"
    cptr += 1

### Parsing the port number.

def p_service_port(p):
    '''service_port : COLON WORD LPAREN NUMBER RPAREN'''
    global parsing_object_type
    if parsing_object_type == 'services':
        if p[2] == 'port':
            current_obj['port'] = p[4]
        elif p[2] == 'protocol':
            current_obj['protocol'] = p[4]

### Parsing a port range.

def p_service_port2(p):
    '''service_port : COLON WORD LPAREN NUMBER WORD RPAREN'''
    global parsing_object_type
    if parsing_object_type == 'services':
        if p[2] == 'port':
            current_obj['portL'] = p[4]
            current_obj['portR'] = p[5][1:]

def p_members(p):
    '''ref_object_begin : COLON LPAREN REFERENCEOBJECT'''
    global parsing_group_attr, cptr, j, parsing_rule_arg
    cptr += 1
    if cptr == 4 and parsing_object_type in {'networks', 'services'}:
        parsing_group_attr = True
    if rule_attr in {'dst', 'src', 'install', 'services'} :
        parsing_rule_arg = True



def p_attr_line1(p):
    '''attr_line : COLON WORD'''
    global parsing_group_attr, current_obj, rule_attr, current_rule
    if parsing_group_attr == True :
        current_obj['members'].append(p[2])
    if rule_attr in {'dst', 'src', 'install', 'services'} :
        current_rule[rule_attr].append(p[2])

def p_attr_line2(p):
    '''attr_line : COLON WORD LPAREN WORD RPAREN'''
    global current_obj, parsing_exception, parsing_group_attr, cptr, parsing_rule_arg, parsing_a_rule,\
        current_rule, rule_attr, members, parsing_object_type

    if parsing_object_type == 'services':
        if p[2] == 'port':
            s = p[4].replace("\"", "")
            signe = s[0]
            port = s[1:]
            if signe == '<':
                current_obj['portL'] = '0'
                current_obj['portR'] = str(int(port)-1)
            elif signe == '>':
                current_obj['portL'] = str(int(port) + 1)
                current_obj['portR'] = 'infinite'
        elif p[2] == 'protocol':
            pass#print p[4]########????????? protocol = -1

    if p[2] == 'Name' and parsing_exception == True:
        current_obj['except_obj'] = p[4]
        #print 'beginning of parsing...exception'
    if p[2] == 'Name' and parsing_group_attr == True:
        members.append(p[4])
        parsing_group_attr = False
    if p[2] == 'name' and parsing_a_rule == True and cptr == 3:
        current_rule['name'] = p[4]

    if p[2] == 'Name' and cptr == 5 and parsing_rule_arg == True:
        if rule_attr in {'dst', 'src', 'install', 'services'} and p[4] not in {'Any', 'any', 'None'}:
            current_rule[rule_attr].append(p[4])
            parsing_rule_arg = False

def p_attr_line3(p):
    '''attr_line : COLON WORD LPAREN ANY RPAREN'''
    pass

### Parsing the protocol. It can be the name or directly the number.




##### Parsing rules ####

def p_begin_rules_line(p):
    '''begin_rules_line : COLON RULEBASE LPAREN WORD'''
    global cptr, current_rule, parsing_object_type, rule_attr
    parsing_object_type = 'rules'
    #print 'begining of parsing...', parsing_object_type, '-->', p[4]
    if cptr == 2: pass

### Parsing the rule number


def p_new_rule_line(p):
    '''new_rule_line : COLON RULE LPAREN'''
    global parsing_a_rule, cptr, current_rule, rule_attr
    cptr += 1
    parsing_a_rule = True
    rule_attr = ''
    current_rule = {'name': None, 'action': None, 'src': [], 'dst': [], 'install': [], 'services': []}


### Begenning to parse the action section

def p_begin_action(p):
    '''begin_action : COLON ACTION LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "action"

### Begenning to parse the destination IP(s) section

def p_begin_dst(p):
    '''begin_dst : COLON DST LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "dst"

### Begenning to parse the "install on" section. It means the name of the firewall
#   on wich the rule is intend to be installed.

def p_begin_install(p):
    '''begin_install : COLON INSTALL LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "install"

### Begenning to parse the source IP(s) section

def p_begin_src(p):
    '''begin_src : COLON SRC LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "src"
    pass

### Begenning to parse the service(s) section



### This is used to parse an exception object (group_with_exclusion for example)

def p_exception_line(p):
    '''exception_line : COLON EXCEPTION LPAREN REFERENCEOBJECT'''
    global parsing_exception, cptr
    parsing_exception = True
    cptr += 1

### Parsing an object attributes like services, destination IPs...



### Parsing other attribute that are not usefull for SpringBok

def p_attr_line(p):
    '''attr_line : COLON LPAREN WORD RPAREN
                 | COLON LPAREN RPAREN
                 | COLON LPAREN ANY RPAREN
                 | COLON OVERLAP_NAT_NETMASK LPAREN IP_ADDR RPAREN
                 | COLON LPAREN NUMBER WORD RPAREN
                 | COLON VALID_IPADDR LPAREN IP_ADDR RPAREN
                 | COLON VERSION LPAREN RPAREN
                 | COLON VERSION LPAREN IP_ADDR RPAREN
                 | COLON VERSION LPAREN NUMBER RPAREN
                 | COLON VERSION LPAREN NUMBER WORD RPAREN
                 | COLON VERSION LPAREN WORD RPAREN
                 | COLON NETOBJ
                 | COLON VERSIONS LPAREN RPAREN
                 | COLON GX_VERSION LPAREN WORD RPAREN
                 | COLON GX_VERSION LPAREN NUMBER RPAREN
                 | COLON GX_VERSION LPAREN NUMBER WORD RPAREN
                 | COLON WORD LPAREN RPAREN
                 | COLON LPAREN NUMBER RPAREN
                 | COLON WORD LPAREN POLICIES_COLLECTIONS RPAREN
                 | COLON SERVOBJ
                 | COLON WORD NUMBER
                 | COLON ACTION LPAREN RPAREN
                 | COLON WORD LPAREN SERVICES RPAREN
                 | COLON TYPE LPAREN DST RPAREN
                 | COLON TYPE LPAREN SRC RPAREN
                 | COLON WORD LPAREN SRC RPAREN
                 | COLON WORD LPAREN DST RPAREN
                 | COLON EDGES LPAREN RPAREN
                 | COLON IPADDR LPAREN RPAREN
                 | COLON NETMASK LPAREN RPAREN
                 | COLON WORD LPAREN NETACCESS RPAREN
                 | COLON WORD LPAREN NETOBJ RPAREN
                 | COLON INTERFACES LPAREN RPAREN
                 | COLON IP_ADDRESS LPAREN IP_ADDR RPAREN
                 | COLON NETWORK_PUBLISH_MASK LPAREN IP_ADDR RPAREN
                 | COLON TYPE LPAREN NUMBER WORD RPAREN
                 '''
    pass


def p_sub(p):
    '''
    sub_obj_attr : COLON LPAREN
                 | COLON WORD LPAREN
                 | COLON WORD LPAREN WORD
                 | COLON WORD LPAREN REFERENCEOBJECT
                 | COLON NETACCESS LPAREN
                 | COLON EDGES LPAREN
                 | COLON RESOURCE LPAREN
                 | COLON NUMBER LPAREN
                 | COLON RESOURCE LPAREN REFERENCEOBJECT
                 | COLON NUMBER LPAREN REFERENCEOBJECT
                 | COLON VERSIONS LPAREN
                 | COLON LPAREN ANY
                 | COLON LPAREN IPADDR
                 | COLON LPAREN DST
                 | COLON LPAREN SRC
                 | COLON LPAREN IP_ADDR
                 | COLON PORTALS LPAREN

    '''
    global cptr
    #if parsing_object_type in {''}
    if p[2] == 'private_ip_ranges' : pass
    cptr += 1


### This line means that we have finish to parse an object. Depending
#   on the value of the counter, and the type of the object, we
#   add the object to object_dict, and to its corrensponding group (gateways,
#   rules, interfaces...

def p_end_obj(p):
    '''end_obj_line : RPAREN'''
    global cptr, current_obj, object_dict, current_fw, firewalls, parsing_group_attr, \
        parsing_object_type, current_rule, rules, services, j, members, rule_attr,\
        parsing_interfaces
    cptr -= 1
    if cptr == 2:
        try :
            if current_obj['type'] in {'host', 'network', 'machines_range', 'services', 'group',
                                       'Group', 'group_with_exclusion', 'dynamic_net_obj'}.union(services):
                object_dict.append(dict(current_obj))
                #print current_obj

            elif current_obj['type'] in {'gateway_cluster', 'gateway'}:
                #print current_obj
                current_fw = dict(current_obj)
                object_dict.append(dict(current_obj))
                current_fw['ifaces'] = list(current_ifaces)
                #print current_ifaces
                firewalls.append(dict(current_fw))
        except KeyError:
                pass
        current_obj.clear()
        current_fw.clear()
        del current_ifaces[:]
        parsing_group_attr = False
        members = []
        if parsing_object_type == 'rules':
            rules.append(dict(current_rule))
           # print current_rule
        current_rule.clear()
        current_rule = {'name': None, 'action': None, 'src': [], 'dst': [], 'install': [], 'services': []}

    elif cptr == 4:
        try:
            if parsing_interfaces == True:
                current_ifaces.append(dict(current_iface))
        except:
            pass
        current_iface.clear()
    elif cptr == 1:
        if parsing_object_type:
            pass
            #print 'end of parsing ', parsing_object_type
        parsing_object_type = ""
    elif cptr == 3:
        if parsing_interfaces == True :
            parsing_interfaces = False
### To manage Syntax errors

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
            s = raw_input('CheckPoint > ')
        except EOFError:
            break
        if not s: continue
        print s
        result = parser.parse(s + '\n')
        print result