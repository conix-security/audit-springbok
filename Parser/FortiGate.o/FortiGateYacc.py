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


######## Modification of the class by Maurice TCHAMGOUE N. on 22-06-2015
###          * Adding the grammar to parse Routes
###          *



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
from SpringBase.Route import Route
import NetworkGraph
import re
import ntpath
import socket


class FirewallVDOM:
    def __init__(self, fw, vdom, used_object, bounded_rules):
        self.fw = fw
        self.vdom = vdom
        self.used_object = set(used_object)
        self.bounded_rules = set(bounded_rules)


# Use for construct dictionary of object and object group
object_dict = {}
parsing_route = False
parsing_ipsec = False
# Use for detect state
p_info = {
    'firewall_list': [],
    'firewall': Firewall(),
    'vdom': None,
    'name': None,
    'hostname': None,
    'srcintf': [],
    'dstintf': [],
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
    'zone_list': {},
    'current_zone': None,
    'route_list': [],
    'current_route' : Route(None, None,None, None,None, 1),
    'index_route': 0,
}


def init(name, raise_on_error=False):
    p_info['firewall_list'] = []
    p_info['raise_on_error'] = raise_on_error
    p_info['use_vdom'] = False
    p_info['name'] = name
    p_info['hostname'] = ntpath.basename(name)
    p_info['current_state'] = []
    p_info['interface_list'] = []
    p_info['zone_list'] = {}
    p_info['current_zone'] = None
    p_info['route_list']= []
    p_info['current_route'] = Route(None, None,None, None,None, 1)
    p_info['index_route'] = 0
    restore_or_create_fw(None)


# restore the firewall context corresponding to vdom or create it
def restore_or_create_fw(vdom):
    # reset to normal state
    _init(vdom)
    # try to restore
    for fw_vdom in p_info['firewall_list']:
        if fw_vdom.vdom == vdom:
            p_info['firewall'] = fw_vdom.fw
            p_info['vdom'] = fw_vdom.vdom
            p_info['used_object'] = fw_vdom.used_object
            p_info['bounded_rules'] = fw_vdom.bounded_rules
            # object_dict = p_info['firewall'].dictionnary not possible (outer scope)
            for k, v in p_info['firewall'].dictionnary.items():
                object_dict[k] = v
            return

    # no fw found : create
    p_info['firewall_list'].append(FirewallVDOM(p_info['firewall'], vdom, p_info['used_object'], p_info['bounded_rules']))


# reset for each VDOM
def _init(vdom):
    object_dict.clear()
    p_info['firewall'] = Firewall()
    p_info['firewall'].name = p_info['name']
    p_info['firewall'].hostname = p_info['hostname'] + ('-' + vdom if vdom else '')
    p_info['firewall'].type = 'Fortinet FortiGate'
    p_info['vdom'] = vdom
    p_info['srcintf'] = []
    p_info['dstintf'] = []
    p_info['used_object'] = set()
    p_info['bounded_rules'] = set()
    p_info['current_rule'] = Rule(None, None, [], [], [], [], [], Action(False))
    p_info['current_interface'] = Interface(None, None, None, [])
    p_info['current_object'] = None
    p_info['range_ip'] = None
    p_info['range_port'] = None
    p_info['route_list']= []
    p_info['current_route'] = Route(None, None,None, None,None, 1)
    p_info['index_route'] = 0


def update():
    pass


def finish():
    print p_info['zone_list']
    p_info['firewall'].dictionnary = dict(object_dict)
    # perform unused object and unbounded rules
    p_info['firewall'].unused_objects = set()
    for k in object_dict:
        if k not in p_info['used_object']:
            p_info['firewall'].unused_objects.add(k)
    p_info['firewall'].route_list = list(p_info['route_list'])


def get_firewall():
    # bind interfaces
    if not p_info['use_vdom']:
        for itf, vdom_name in p_info['interface_list']:
            p_info['firewall'].interfaces.append(itf)
    else:
        for itf, vdom_name in p_info['interface_list']:
            for fw_vdom in p_info['firewall_list']:
                if fw_vdom.vdom == vdom_name:
                    fw_vdom.fw.interfaces.append(itf)
                    break

    return [fw_vdom.fw for fw_vdom in p_info['firewall_list']]


def show():
    print "--------- Object ---------"
    for k, v in object_dict.items():
        print '%s :' % k
        for elem in v:
            for k1, v1 in elem.items():
                print '\t%s %s' % (k1, v1)
    print "--------- Firewall ---------"
    print "%s" % p_info['firewall'].to_string()


def try_resolve_service(name):
    if re.search('icmp6', name, re.I) or re.search('ping', name, re.I):
        p_info['current_rule'].protocol.append(Operator('EQ', Protocol('icmp')))
        return True

    try:
        # try port
        p_info['current_rule'].port_dest.append(Operator('EQ', Port(name)))
        p_info['current_rule'].protocol.append(Operator('EQ', Protocol('tcp')))
    except socket.error:
        # not a port, try protocol
        try:
            p_info['current_rule'].protocol.append(Operator('EQ', Protocol(name)))
        except socket.error:
            # not a port or a protocol
            return False
    return True


def resolve(name, src_dest=None):
    if name not in object_dict:
        if src_dest == 'service' and try_resolve_service(name.lower()):
            return
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
    for src_itf in p_info['srcintf']:
        for dst_itf in p_info['dstintf']:
            acl = p_info['firewall'].get_acl_by_name(src_itf + '-' + dst_itf)

            if not acl:
                acl = ACL(src_itf + '-' + dst_itf)
                p_info['firewall'].acl.append(acl)
                s_itf = None
                d_itf = None
                for itf, vdom_name in p_info['interface_list']:
                    if itf.nameif == src_itf:
                        s_itf = itf
                    elif itf.nameif == dst_itf:
                        d_itf = itf
                NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(acl,
                                                                  p_info['firewall'],
                                                                  s_itf,
                                                                  d_itf)

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

def retrieve_if(nameif):
    for k, v in p_info['interface_list']:
            if k.nameif == nameif.replace("\"", ''):
                return k


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
            | zone_line NL
            | zone_set_line NL
            | config_line NL
            | end_line NL
            | next_line NL
            | begin_route_line NL
            | route_attr_line NL
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
    # We use vdom so we remove the first firewall of the list because it does not belong
    if not p_info['use_vdom']:
        p_info['use_vdom'] = True
        p_info['firewall_list'].pop()
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
        p_info['hostname'] = hostname
        p_info['firewall'].hostname = hostname + ('-' + p_info['vdom'] if p_info['vdom'] else '')
        for fw_vdom in p_info['firewall_list']:
            fw_vdom.fw.hostname = hostname + '-' + (fw_vdom.vdom if fw_vdom.vdom else '')


# edit line

def p_edit_line(p):
    '''edit_line : EDIT NUMBER
                 | EDIT WORD'''
    if get_state() == 'vdom':
        finish()  # finish
        restore_or_create_fw(p[2])  # reset to a new firewall
    elif get_state() == 'policy':
        p_info['current_rule'] = Rule(int(p[2]), None, [], [], [], [], [], Action(False))
        p_info['srcintf'] = []
        p_info['dstintf'] = []
    elif get_state() in ('address', 'address_group', 'service', 'service_group'):
        object_dict[remove_quote(p[2])] = []
        p_info['current_object'] = remove_quote(p[2])
        p_info['range_ip'] = None
        p_info['range_port'] = None
    elif get_state() == 'interface':
        p_info['current_interface'] = Interface(remove_quote(p[2]), None, None, [])
        p_info['interface_list'].append([p_info['current_interface'], None])
    elif get_state() == 'zone':
        p_info['zone_list'][remove_quote(p[2])] = []
        p_info['current_zone'] = remove_quote(p[2])
    elif parsing_route == True:
        p_info['current_route'].id = int(p[2])


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
    '''addr_set_line : SET SUBNET IP_ADDR SLASH NUMBER'''
    object_dict[p_info['current_object']].append({'address': Operator('EQ', Ip(p[3], Ip.CidrToMask(int(p[5]))))})


## config addr service
def p_addr_service_line(p):
    '''config_service_line : CONFIG SERVICE'''
    push_state('service_address')

### service address end port
def p_addr_service_set_line_1(p):
    '''service_set_line : SET END_PORT NUMBER'''
    if p_info['range_port']:
        object_dict[p_info['current_object']].append({'port_dst': Operator('RANGE', p_info['range_port'], Port(p[3]))})
        p_info['range_port'] = None
    else:
        p_info['range_port'] = Port(p[3])

### service address protocol -> redirect service_set_line
def p_addr_service_set_line_2(p):
    '''service_set_line : service_set_line'''

### service address start port
def p_addr_service_set_line_3(p):
    '''service_set_line : SET START_PORT NUMBER'''
    if p_info['range_port']:
        object_dict[p_info['current_object']].append({'port_dst': Operator('RANGE', Port(p[3]), p_info['range_port'])})
        p_info['range_port'] = None
    else:
        p_info['range_port'] = Port(p[3])


### subnet 2
def p_addr_set_line_6(p):
    '''addr_set_line : SET WILDCARD IP_ADDR IP_ADDR'''
    object_dict[p_info['current_object']].append({'address': Operator('EQ', Ip(p[3], p[4]))})


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
def p_service_set_line_3_1(p):
    '''service_set_line : SET PROTOCOL WORD'''
    if p[3].lower() in ('ftp', 'http'):
        object_dict[p_info['current_object']].append({'port_dst': Operator('EQ', Port(p[3].lower()))})
    else:
        object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol(p[3].lower()))})


def p_service_set_line_3_2(p):
    '''service_set_line : SET PROTOCOL_NUMBER NUMBER'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol(p[3]))})


def p_service_set_line_3_3(p):
    '''service_set_line : SET PROTOCOL IP'''


def p_service_set_line_3_4(p):
    '''service_set_line : SET PROTOCOL TCP_UDP_SCTP'''
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol('tcp'))})
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol('udp'))})
    object_dict[p_info['current_object']].append({'protocol': Operator('EQ', Protocol('sctp'))})


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
    if get_state() in ('address', 'address_group', 'service', 'service_group'):
        object_dict[p_info['current_object']].append({'object': remove_quote(p[1])})
    elif get_state() == 'interface':
        if p_info['current_interface'].nameif not in p_info['zone_list']:
            p_info['zone_list'][p_info['current_interface'].nameif] = []
        p_info['zone_list'][p_info['current_interface'].nameif].append(remove_quote(p[1]))


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
    if get_state() == 'interface':
        p_info['current_interface'].network = Ip(p[3], p[4])


### interface name
def p_interface_set_line_2(p):
    '''interface_set_line : SET ALIAS WORD'''
    if get_state() == 'interface':
        if p_info['current_interface'].name:
            p_info['current_interface'].name += remove_quote(p[3])
        else:
            p_info['current_interface'].name = remove_quote(p[3])


### interface vland
def p_interface_set_line_3(p):
    '''interface_set_line : SET VLANID NUMBER'''
    if get_state() == 'interface':
        p_info['current_interface'].attributes['vlanid'] = p[3]

# zone

current_zone = ''
### zone line
def p_zone_line(p):
    '''zone_line : CONFIG SYSTEM ZONE'''
    push_state('zone')


### zone_set
def p_zone_set_line(p):
    '''zone_set_line : SET INTERFACE zone_words'''


def p_zone_words(p):
    '''zone_words : WORD
                  | WORD zone_words'''
    print 'theme'
    print p[1]
    print p[2]
    if get_state() == 'zone' and p_info['current_zone']:
        p_info['zone_list'][p_info['current_zone']].append(remove_quote(p[1]))

    elif get_state() == 'interface' and p_info['current_interface']:
        if p_info['current_interface'].name:
            p_info['current_interface'].name += ', '
        else:
            p_info['current_interface'].name = ''
        p_info['current_interface'].name += remove_quote(p[1])
        if remove_quote(p[1]) in p_info['zone_list']:
            p_info['current_interface'].name += ' (' + ', '.join(p_info['zone_list'][remove_quote(p[1])]) + ')'

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
        p_info['current_rule'].name = remove_quote(p[3])


### service line
def p_policy_set_line_5(p):
    '''policy_service_line : SET SERVICE service_words'''


### service words variables
def p_service_words(p):
    '''service_words : WORD service_words
                     | WORD'''
    if get_state() == 'policy':
        resolve(remove_quote(p[1]), 'service')


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
    '''policy_set_line : SET SRC_INTF itf_words'''
    if get_state() == 'policy':
        p_info['srcintf'] = p[3]
        if p_info['dstintf']:
            add_rule(p_info['current_rule'])


def p_policy_set_line_8(p):
    '''policy_set_line : SET DST_INTF itf_words'''
    if get_state() == 'policy':
        p_info['dstintf'] = p[3]
        if p_info['srcintf']:
            add_rule(p_info['current_rule'])


def p_itf_words_1(p):
    '''itf_words : WORD'''
    test = remove_quote(p[1])
    if re.search('any', test, re.I):
        p[0] = [itf[0].nameif for itf in p_info['interface_list']]
    if test in p_info['zone_list']:
        p[0] = p_info['zone_list'][test]
    else:
        p[0] = [test]


def p_itf_words_2(p):
    '''itf_words : WORD itf_words'''
    test = remove_quote(p[1])
    if re.search('any', test, re.I):
        p[0] = [itf[0].nameif for itf in p_info['interface_list']] + p[2]
    elif test in p_info['zone_list']:
        p[0] = p_info['zone_list'][test] + p[2]
    else:
        p[0] = [test] + p[2]


def p_policy_set_line_9(p):
    '''policy_set_line : STATUS DISABLE'''
    if get_state() == 'policy':
        remove_rule(p_info['current_rule'].identifier)


def p_policy_set_line_10(p):
    '''policy_set_line : SET PERMIT_ANY_HOST WORD
                       | SET PERMIT_STUN_HOST WORD'''
    if get_state() == 'policy':
        if re.search('enable', p[3], re.I):
            p_info['current_rule'].protocol.append(Operator('EQ', Protocol('udp')))


### dst address negate
def p_policy_set_line_11(p):
    '''policy_set_line : SET DST_ADDR_NEGATE WORD'''
    if re.match('enable', p[3], re.I):
        res = []
        for op in p_info['current_rule'].ip_dest:
            res += op.toggle()
        p_info['current_rule'].ip_dest = res


### src address negate
def p_policy_set_line_12(p):
    '''policy_set_line : SET SRC_ADDR_NEGATE WORD'''
    if re.match('enable', p[3], re.I):
        res = []
        for op in p_info['current_rule'].ip_source:
            res += op.toggle()
        p_info['current_rule'].ip_source = res


# config error

def p_config_error(p):
    '''config_line : CONFIG error'''
    push_state('error-' + p[2].value)


# end_next_line

def p_end_line(p):
    '''end_line : END'''
    global parsing_route, parsing_ipsec
    pop_state()
    if parsing_route == True:
        parsing_route = False
    if parsing_ipsec == True:
        parsing_ipsec = False

# next line

def p_next_line(p):
    '''next_line : NEXT'''
    global parsing_route
    if parsing_route == True:
        p_info['route_list'].append(p_info['current_route'])
        p_info['current_route'] = Route(None, None,None, None,None, 1)



def p_error(p):
    if p_info['raise_on_error']:
        if p:
            print("Syntax error at '%s'" % p.value)
        else:
            print("Syntax error at EOF")
        raise SyntaxError

####### Parsing Routes ########

def p_begin_route_line(p):
    '''begin_route_line : CONFIG WORD WORD'''
    global parsing_route
    if p[2] == 'router' and p[3] == 'static':
        parsing_route = True

def p_route_attr_line(p):
    '''route_attr_line : SET WORD WORD'''
    global parsing_route
    if p[2] == 'comment' and parsing_route == True:
        p_info['current_route'].name = p[3].replace("\"", '')
    elif p[2] == 'device' and parsing_route == True:
        p_info['current_route'].iface = retrieve_if(p[3])

def p_route_attr_line2(p):
    '''route_attr_line : SET DST IP_ADDR IP_ADDR'''
    global parsing_route
    if parsing_route == True:
        p_info['current_route'].net_ip_dst = Ip(p[3])
        p_info['current_route'].net_mask = Ip(p[4])


def p_route_attr_line3(p):
    '''route_attr_line : SET GATEWAY IP_ADDR'''
    global parsing_route
    if parsing_route == True:
        p_info['current_route'].gw_ip = Ip(p[3])

def p_ipsec_begin_line(p):
    '''ipsec_begin_line : CONFIG VPN IPSEC words'''
    global parsing_ipsec
    parsing_ipsec = True




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

