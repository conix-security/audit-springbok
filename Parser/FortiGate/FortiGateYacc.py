#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Fortigate parser.
Each parser construct their firewall as they want,
but they must implement some function :
- init(name, raise_on_error=False)
- update():
- finish():
- get_firewall():
- show():
"""

from Parser.ply import yacc
from Parser.FortiGate.FortiGateLex import tokens
from Parser.FortiGate.FortiGateLex import lexer
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


# Use for construct dictionary of object and object group
object_dict = {}

# Use for detect state
p_info = {
    'firewall_list': [],
    'firewall': Firewall(),
    'vdom': None,
    'name': None,
    'hostname': None,
    'srcintf': None,
    'dstintf': None,
    'used_object': set(),
    'bounded_rules': set(),
    'current_rule': Rule(None, None, [], [], [], [], [], Action(False)),
    'current_interface': Interface(None, None, None, []),
    'current_object': None,
    'current_state': [],
    'range_ip': None,
    'range_port': None,
    'raise_on_error': False,
    'use_vdom': False,
    'interface_list': [],
}


def init(name, raise_on_error=False):
    p_info['firewall_list'] = []
    p_info['raise_on_error'] = raise_on_error
    p_info['use_vdom'] = False
    p_info['name'] = name
    p_info['hostname'] = ntpath.basename(name)
    p_info['current_state'] = []
    p_info['interface_list'] = []
    _init(None)


# reset for each VDOM
def _init(vdom):
    object_dict.clear()
    p_info['firewall'] = Firewall()
    p_info['firewall'].name = p_info['name']
    p_info['firewall'].hostname = p_info['hostname'] + ('-' + vdom if vdom else '')
    p_info['firewall'].type = 'Fortinet FortiGate'
    p_info['vdom'] = vdom
    p_info['srcintf'] = None
    p_info['dstintf'] = None
    p_info['used_object'] = set()
    p_info['bounded_rules'] = set()
    p_info['current_rule'] = Rule(None, None, [], [], [], [], [], Action(False))
    p_info['current_interface'] = Interface(None, None, None, [])
    p_info['current_object'] = None
    p_info['range_ip'] = None
    p_info['range_port'] = None


def update():
    pass


def finish():
    p_info['firewall'].dictionnary = dict(object_dict)
    # perform unused object and unbounded rules
    for k in object_dict:
        if k not in p_info['used_object']:
            p_info['firewall'].unused_objects.add(k)
    if not (p_info['use_vdom'] and p_info['vdom'] is None):
        p_info['firewall_list'].append(p_info['firewall'])


def get_firewall():
    # bind interfaces
    for itf, vdom_name in p_info['interface_list']:
        if not vdom_name or vdom_name == 'root':
            p_info['firewall'].interfaces.append(itf)
            continue
        for fw in p_info['firewall_list']:
            if len(fw.hostname) > len(vdom_name) and fw.hostname[len(fw.hostname) - len(vdom_name):] == vdom_name:
                fw.interfaces.append(itf)
                break

    return p_info['firewall_list']


def show():
    print "--------- Object ---------"
    for k, v in object_dict.items():
        print '%s :' % k
        for elem in v:
            for k1, v1 in elem.items():
                print '\t%s %s' % (k1, v1)
    print "--------- Firewall ---------"
    print "%s" % p_info['firewall'].to_string()


def resolve(name, src_dest=None):
    if name not in object_dict:
        print 'Critical: %s not found in dictionary' % name
        raise SyntaxError

    p_info['used_object'].add(name)
    values = object_dict[name]

    for elem in values:
        for k1, v1 in elem.items():
            if k1 == 'object':
                resolve(v1, src_dest)
            if k1 == 'address':
                if src_dest == 'src':
                    p_info['current_rule'].ip_source.append(v1)
                    p_info['current_rule'].ip_source_name.append(name)
                else:
                    p_info['current_rule'].ip_dest.append(v1)
                    p_info['current_rule'].ip_dest_name.append(name)
            elif k1 == 'protocol':
                p_info['current_rule'].protocol.append(v1)
                p_info['current_rule'].protocol_name.append(name)
            elif k1 == 'port_src':
                p_info['current_rule'].port_source.append(v1)
                p_info['current_rule'].port_source_name.append(name)
            elif k1 == 'port_dst':
                p_info['current_rule'].port_dest.append(v1)
                p_info['current_rule'].port_dest_name.append(name)


def add_rule(rule):
    acl = p_info['firewall'].get_acl_by_name(p_info['srcintf'] + '-' + p_info['dstintf'])

    if not acl:
        acl = ACL(p_info['srcintf'] + '-' + p_info['dstintf'])
        p_info['firewall'].acl.append(acl)
        src_itf = None
        dst_itf = None
        for itf, vdom_name in p_info['interface_list']:
            if itf.nameif == p_info['srcintf']:
                src_itf = itf
            elif itf.nameif == p_info['dstintf']:
                dst_itf = itf
        NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(acl,
                                                          p_info['firewall'],
                                                          src_itf,
                                                          dst_itf)

    acl.rules.append(rule)


# remove the rule who his identifier match id
def remove_rule(id):
    p_info['firewall'].del_rule_by_id(id)
    for fw in p_info['firewall_list']:
        fw.del_rule_by_id(id)


# remove quote from variable name if any
def remove_quote(name):
    if re.match(r'\".*\"', name):
        return name[1:-1]
    return name


def push_state(state):
    p_info['current_state'].append(state)


def pop_state():
    if p_info['current_state']:
        return p_info['current_state'].pop()


def get_state():
    if p_info['current_state']:
        return p_info['current_state'][-1]
    return None


########################## Grammar ############################


def p_lines(p):
    '''lines : line
             | line lines'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + '\n' + p[2]


def p_line(p):
    '''line : config_vdom_line NL
            | set_vdom_line NL
            | config_system_line NL
            | hostname_line NL
            | policy_line NL
            | edit_line NL
            | interface_set_line NL
            | group_set_line NL
            | policy_service_line NL
            | service_group_line NL
            | addr_line NL
            | addr_set_line NL
            | service_line NL
            | service_set_line NL
            | config_service_line NL
            | addrgrp_line NL
            | policy_set_line NL
            | interface_line NL
            | config_line NL
            | end_line NL
            | next_line NL
            | words NL
            | NL'''
    p[0] = p[1]


# Usefull expression
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


### words
def p_words_1(p):
    '''words : WORD'''
    p[0] = p[1]


def p_words_2(p):
    '''words : WORD words'''
    p[0] = p[1] + ' ' + p[2]


# config vdom
def p_config_vdom(p):
    '''config_vdom_line : CONFIG VDOM'''
    p_info['use_vdom'] = True
    push_state('vdom')


# set vdom line
def p_set_vdom_line(p):
    '''set_vdom_line : SET VDOM WORD'''
    if get_state() == 'interface':
        p_info['interface_list'][-1][1] = remove_quote(p[3])


# config system global
def p_config_system_line(p):
    '''config_system_line : CONFIG SYSTEM GLOBAL'''
    push_state('config_global')


# hostname
def p_hostname_line(p):
    '''hostname_line : SET HOSTNAME WORD'''
    if get_state() == 'config_global':
        hostname = remove_quote(p[3])
        p_info['firewall'].hostname = hostname + ('-' + p_info['vdom'] if p_info['vdom'] else '')
        for fw in p_info['firewall_list']:
            fw.hostname.replace(p_info['hostname'], hostname, 1)
        p_info['hostname'] = hostname


# edit line

def p_edit_line(p):
    '''edit_line : EDIT NUMBER
                 | EDIT WORD'''
    if get_state() == 'vdom':
        finish()  # finish
        _init(p[2])  # reset to a new firewall
    elif get_state() == 'policy':
        p_info['current_rule'] = Rule(int(p[2]), None, [], [], [], [], [], False)
        p_info['srcintf'] = None
        p_info['dstintf'] = None
    elif get_state() in ('address', 'address_group', 'service', 'service_group'):
        object_dict[remove_quote(p[2])] = []
        p_info['current_object'] = remove_quote(p[2])
        p_info['range_ip'] = None
        p_info['range_port'] = None
    elif get_state() == 'interface':
        p_info['current_interface'] = Interface(remove_quote(p[2]), None, None, [])
        p_info['interface_list'].append([p_info['current_interface'], None])


# address parse

### address line
def p_addr_line(p):
    '''addr_line : CONFIG FIREWALL ADDRESS'''
    push_state('address')


### end_ip
def p_addr_set_line_1(p):
    '''addr_set_line : SET END_IP IP_ADDR'''
    if p_info['range_ip']:
        object_dict[p_info['current_object']].append({'address': Operator('RANGE', p_info['range_ip'], Ip(p[3]))})
        p_info['range_ip'] = None
    else:
        p_info['range_ip'] = Ip(p[3])

### fqdn set line (used also for service definition)
def p_addr_set_line_2(p):
    '''addr_set_line : SET FQDN WORD'''
    object_dict[p_info['current_object']].append({'address': Operator('EQ', Ip(socket.gethostbyname(remove_quote(p[3]))))})

### start-ip
def p_addr_set_line_3(p):
    '''addr_set_line : SET START_IP IP_ADDR'''
    if p_info['range_ip']:
        object_dict[p_info['current_object']].append({'address': Operator('RANGE', Ip(p[3]), p_info['range_ip'])})
        p_info['range_ip'] = None
    else:
        p_info['range_ip'] = Ip(p[3])

### subnet 1
def p_addr_set_line_4(p):
    '''addr_set_line : SET SUBNET IP_ADDR IP_ADDR'''
    object_dict[p_info['current_object']].append({'address': Operator('EQ', Ip(p[3], p[4]))})

### subnet 2
def p_addr_set_line_5(p):
    '''addr_set_line : SET SUBNET IP_ADDR SLASH IP_ADDR'''
    object_dict[p_info['current_object']].append({'address': Operator('EQ', Ip(p[3], Ip.CidrToMask(int(p[4]))))})


## config addr service
def p_addr_service_line(p):
    '''config_service_line : CONFIG SERVICE'''
    push_state('service_address')

### service address end port
def p_addr_service_set_line_1(p):
    '''service_set_line : END_PORT NUMBER'''
    if p_info['range_port']:
        object_dict[p_info['current_object']].append({'port_dst': Operator('RANGE', p_info['range_port'], Port(p[2]))})
        p_info['range_port'] = None
    else:
        p_info['range_port'] = Port(p[2])

### service address protocol
def p_addr_service_set_line_2(p):
    '''service_set_line : PROTOCOL WORD'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol(p[2]))})

### service address start port
def p_addr_service_set_line_3(p):
    '''service_set_line : START_PORT NUMBER'''
    if p_info['range_port']:
        object_dict[p_info['current_object']].append({'port_dst': Operator('RANGE', Port(p[2]), p_info['range_port'])})
        p_info['range_port'] = None
    else:
        p_info['range_port'] = Port(p[2])


# service parse

### service line
def p_service_line(p):
    '''service_line : CONFIG FIREWALL SERVICE CUSTOM'''
    push_state('service')


### ip set line 1
def p_service_set_line_2_1(p):
    '''service_set_line : SET IPRANGE IP_ADDR'''
    object_dict[p_info['current_object']].append({'address': Operator('EQ', Ip(p[3]))})


### ip set line 2
def p_service_set_line_2_2(p):
    '''service_set_line : SET IPRANGE IP_ADDR MINUS IP_ADDR'''
    object_dict[p_info['current_object']].append({'address': Operator('RANGE', Ip(p[3]), Ip(p[5]))})


### protocol set line
def p_service_set_line_3(p):
    '''service_set_line : SET PROTOCOL WORD
                        | SET PROTOCOL_NUMBER NUMBER'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol(p[3]))})


### sctp port range
def p_service_set_line_4(p):
    '''service_set_line : SET SCTP_PORTRANGE port_services'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol('SCTP'))})


### tcp port range
def p_service_set_line_5(p):
    '''service_set_line : SET TCP_PORTRANGE port_services'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol('TCP'))})


### udp port range
def p_service_set_line_6(p):
    '''service_set_line : SET UDP_PORTRANGE port_services'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol('UDP'))})


### port services for custom service definition
def p_port_services(p):
    '''port_services : port_service port_services
                     | port_service'''


### port service definition 1
def p_port_service_1(p):
    '''port_service : NUMBER'''
    object_dict[p_info['current_object']].append({'port_dst': Operator('EQ', Port(p[1]))})


### port service definition 2
def p_port_service_2(p):
    '''port_service : NUMBER MINUS NUMBER'''
    object_dict[p_info['current_object']].append({'port_dst': Operator('RANGE', Port(p[1]), Port(p[3]))})


### port service definition 3
def p_port_service_3(p):
    '''port_service : NUMBER MINUS NUMBER COLON NUMBER MINUS NUMBER'''
    object_dict[p_info['current_object']].append({'port_dst': Operator('RANGE', Port(p[1]), Port(p[3]))})
    object_dict[p_info['current_object']].append({'port_src': Operator('RANGE', Port(p[5]), Port(p[7]))})


# member list

def p_member_list(p):
    '''member_list : WORD
                   | WORD member_list'''
    object_dict[p_info['current_object']].append({'object': remove_quote(p[1])})


### group set line
def p_group_set_line_1(p):
    '''group_set_line : SET MEMBER member_list'''


# address group

### addrgrp line
def p_addrgrp_line(p):
    '''addrgrp_line : CONFIG FIREWALL ADDRGRP'''
    push_state('address_group')


# service group

### service group line
def p_service_group_line(p):
    '''service_group_line : CONFIG FIREWALL SERVICE GROUP'''
    push_state('service_group')


# interface

### interface line
def p_interface_line(p):
    '''interface_line : CONFIG SYSTEM INTERFACE'''
    push_state('interface')


### interface ip addr
def p_interface_set_line_1(p):
    '''interface_set_line : SET IP IP_ADDR IP_ADDR'''
    p_info['current_interface'].network = Ip(p[3], p[4])


### interface name
def p_interface_set_line_2(p):
    '''interface_set_line : SET ALIAS WORD'''
    p_info['current_interface'].name = remove_quote(p[3])


# policy parse

### policy_line
def p_policy_line(p):
    '''policy_line : CONFIG FIREWALL POLICY'''
    push_state('policy')


### action line
def p_policy_set_line_1(p):
    '''policy_set_line : SET ACTION ACCEPT'''
    if get_state() == 'policy':
        p_info['current_rule'].action = Action(True)


def p_policy_set_line_2(p):
    '''policy_set_line : SET ACTION DENY'''
    if get_state() == 'policy':
        p_info['current_rule'].action = Action(False)


### dst address line
def p_policy_set_line_3(p):
    '''policy_set_line : SET DST_ADDR dst_addr_words'''


### dst address words variables
def p_dst_address_words(p):
    '''dst_addr_words : WORD dst_addr_words
                      | WORD'''
    if get_state() == 'policy':
        resolve(remove_quote(p[1]), 'dst')


### label line
def p_policy_set_line_4(p):
    '''policy_set_line : SET LABEL words'''
    if get_state() == 'policy':
        p_info['current_rule'].name = remove_quote(p[2])


### service line
def p_policy_set_line_5(p):
    '''policy_service_line : SET SERVICE service_words'''


### service words variables
def p_service_words(p):
    '''service_words : WORD service_words
                     | WORD'''
    if get_state() == 'policy':
        resolve(remove_quote(p[1]))


### src address line
def p_policy_set_line_6(p):
    '''policy_set_line : SET SRC_ADDR src_addr_words'''


### src addr words variables
def p_src_addr_words(p):
    '''src_addr_words : WORD src_addr_words
                     | WORD'''
    if get_state() == 'policy':
        resolve(remove_quote(p[1]), 'src')


### interface line
def p_policy_set_line_7(p):
    '''policy_set_line : SET SRC_INTF words'''
    if get_state() == 'policy':
        p_info['srcintf'] = remove_quote(p[3])
        if p_info['dstintf']:
            add_rule(p_info['current_rule'])


def p_policy_set_line_8(p):
    '''policy_set_line : SET DST_INTF words'''
    if get_state() == 'policy':
        p_info['dstintf'] = remove_quote(p[3])
        if p_info['srcintf']:
            add_rule(p_info['current_rule'])


def p_policy_set_line_9(p):
    '''policy_set_line : STATUS DISABLE'''
    if get_state() == 'policy':
        remove_rule(p_info['current_rule'].identifier)


# config word

def p_config_word(p):
    '''config_line : CONFIG words'''
    push_state(p[2])


# end_next_line

def p_end_line(p):
    '''end_line : END'''
    pop_state()

# next line

def p_next_line(p):
    '''next_line : NEXT'''


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
            s = raw_input('FortiGate > ')
        except EOFError:
            break
        if not s: continue
        print s
        result = parser.parse(s + '\n')
        print result

