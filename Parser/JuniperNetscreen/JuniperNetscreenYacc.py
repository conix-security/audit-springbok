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
from Parser.JuniperNetscreen.JuniperNetscreenLex import tokens
from Parser.JuniperNetscreen.JuniperNetscreenLex import lexer
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
    'raise_on_error': False,
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
    p_info['raise_on_error'] = raise_on_error


def update():
    pass


def finish():
    p_info['firewall'].dictionnary = dict(object_dict)
    for k in object_dict:
        if k not in p_info['used_object']:
            p_info['firewall'].unused_objects.add(k)


def get_firewall():
    return [p_info['firewall']]


def show():
    print "--------- Object ---------"
    for k, v in object_dict.items():
        print '%s :' % k
        for elem in v:
            for k1, v1 in elem.items():
                if k1 == 'object':
                    print '\t%s %s' % (k1, v1)
                else:
                    print '\t%s %s' % (k1, v1.to_string())
    print "--------- Firewall ---------"
    print "%s" % p_info['firewall'].to_string()


def insert_rule():
    if p_info['policy_zone_src'] and p_info['policy_zone_dst']:
        acl = p_info['firewall'].get_acl_by_name(p_info['policy_zone_src'] + '-' + p_info['policy_zone_dst'])

        if not acl:
            acl = ACL(p_info['policy_zone_src'] + '-' + p_info['policy_zone_dst'])
            p_info['firewall'].acl.append(acl)
            NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(acl,
                                                              p_info['firewall'],
                                                              p_info['firewall'].get_interface_by_name(p_info['policy_zone_src']),
                                                              p_info['firewall'].get_interface_by_name(p_info['policy_zone_dst']))

        if p_info['index_rule'] != -1:
            acl.rules.insert(p_info['index_rule'], p_info['current_policy'])
        else:
            acl.rules.append(p_info['current_policy'])
    else:
        for acl in p_info['firewall'].acl:
            acl.rules.append(p_info['current_policy'])

    p_info['current_policy'] = Rule(0, "", [], [], [], [], [], Action(False))
    p_info['policy_zone_src'] = None
    p_info['policy_zone_dst'] = None
    p_info['index_rule'] = -1


def move_rule(i1, pos, i2):
    rule1 = None
    for acl in p_info['firewall'].acl:
        for rule in acl.rules:
            if rule.identifier == i1:
                rule1 = rule
                break
        for rule in acl.rules:
            if rule.identifier == i2:
                acl.rules.remove(rule1)
                index = p_info['firewall'].rules.index(rule) + 0 if pos == 'before' else 1
                p_info['firewall'].rules.insert(index, rule1)


def resolve_predefined_juniper(name, policy):
    values = JuniperNetscreenPort.JuniperNetscreenPort[name]

    for v1, v2 in values:
        if v1 == 'protocol':
            policy.protocol.append(Operator('EQ', Protocol(v2)))
            policy.protocol_name.append(name)
        else:
            port = policy.port_source if v1 == 'src' else policy.port_dest
            port_name = policy.port_source_name if v1 == 'src' else policy.port_dest_name
            port_name.append(name)
            if isinstance(v2, str):
                res = v2.split('-')
                port.append(Operator('RANGE', Port(res[0]), Port(res[1])))
            if isinstance(v2, list):
                for i in v2:
                    port.append(Operator('EQ', Port(i)))
            else:
                port.append(Operator('EQ', Port(v2)))


def resolve(name, policy, src_dst=None):
    if name not in object_dict:
        if name not in JuniperNetscreenPort.JuniperNetscreenPort:
            if 'ICMP' in name or name in ('Traceroute', 'PING'):
                policy.protocol.append(Operator('EQ', Protocol('icmp')))
                policy.protocol_name.append(name)
            else:
                print 'Critical: %s not found in dictionary' % name
                raise SyntaxError
        else:
            resolve_predefined_juniper(name, policy)
    else:
        p_info['used_object'].add(name)
        values = object_dict[name]

        for elem in values:
            for k1, v1 in elem.items():
                if k1 == 'object':
                    resolve(v1, policy, src_dst)
                elif k1 == 'address':
                    if src_dst == 'src':
                        policy.ip_source.append(v1)
                        policy.ip_source_name.append(name)
                    else:
                        policy.ip_dest.append(v1)
                        policy.ip_dest_name.append(name)
                elif k1 == 'service':
                    policy.protocol.append(v1)
                    policy.protocol_name.append(name)
                elif k1 == 'src-port':
                    policy.port_source.append(v1)
                    policy.port_source_name.append(name)
                elif k1 == 'dst-port':
                    policy.port_dest.append(v1)
                    policy.port_dest_name.append(name)


def remove_quote(name):
    if re.match(r'\".*\"', name):
        return name[1:-1]
    return name


precedence = (
    ('left', 'NUMBER'),
)


def p_lines(p):
    '''lines : line
             | line lines'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + '\n' + p[2]


def p_line(p):
    '''line : hostname_line NL
            | policy_line NL
            | policy_id_line NL
            | words NL
            | policy_context_line NL
            | address_line NL
            | service_line NL
            | group_line NL
            | interface_line NL
            | EXIT NL
            | NL'''
    p[0] = p[1]


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


def p_object_name(p):
    '''object_name : WORD'''
    p[0] = remove_quote(p[1])


# hostname

### hostname_line
def p_hostname_line(p):
    '''hostname_line : SET HOSTNAME words'''
    p_info['firewall'].hostname = p[3]


# Variables

## address

### address_line
def p_address_line_1(p):
    '''address_line : SET ADDRESS WORD object_name WORD words'''
    object_dict[p[4]] = [{'address': Operator('EQ', Ip(socket.gethostbyname(p[5])))}]


def p_address_line_2(p):
    '''address_line : SET ADDRESS WORD object_name IP_ADDR IP_ADDR
                    | SET ADDRESS WORD object_name IP_ADDR IP_ADDR words'''
    object_dict[p[4]] = [{'address': Operator('EQ', Ip(p[5], p[6]))}]


## service

### service_line
def p_service_line_1(p):
    '''service_line : SET SERVICE object_name service_plus'''
    object_dict[p[3]] += p_info['current_object']
    p_info['current_object'] = []


def p_service_line_2(p):
    '''service_line : SET SERVICE object_name service_protocol'''
    object_dict[p[3]] = p_info['current_object']
    p_info['current_object'] = []


def p_service_line(p):
    '''service_line : SET SERVICE WORD TIMEOUT items
                    | SET SERVICE WORD SESSION_CACHE'''


### service_plus
def p_service_plus_1(p):
    '''service_plus : PLUS ICMP TYPE NUMBER CODE NUMBER'''
    p_info['current_object'].append({'service': Operator('EQ', Protocol('icmp'))})


def p_service_plus_2(p):
    '''service_plus : PLUS protocol SRC_PORT NUMBER HYPHEN NUMBER DST_PORT NUMBER HYPHEN NUMBER'''
    p_info['current_object'].append({'service': Operator('EQ', Protocol(p[2]))})
    p_info['current_object'].append({'src-port': Operator('RANGE', Port(p[4]), Port(p[6]))})
    p_info['current_object'].append({'dst-port': Operator('RANGE', Port(p[8]), Port(p[10]))})


def p_service_plus_3(p):
    '''service_plus : PLUS WORD items'''


### service_protocol
def p_service_protocol_1(p):
    '''service_protocol : PROTOCOL protocol opt_protocol_src opt_protocol_dst'''
    p_info['current_object'].append({'service': Operator('EQ', Protocol(p[2]))})


def p_service_protocol_2(p):
    '''service_protocol : PROTOCOL ICMP TYPE NUMBER CODE NUMBER'''
    p_info['current_object'].append({'service': Operator('EQ', Protocol('icmp'))})


def p_service_protocol_3(p):
    '''service_protocol : PROTOCOL WORD items'''


### opt_protocol_src
def p_opt_protocol_src_1(p):
    '''opt_protocol_src : SRC_PORT NUMBER HYPHEN NUMBER'''
    p_info['current_object'].append({'src-port': Operator('RANGE', Port(p[2]), Port(p[4]))})


def p_opt_protocol_src_2(p):
    '''opt_protocol_src : empty'''


### opt_protocol_dst
def p_opt_protocol_dst_1(p):
    '''opt_protocol_dst : DST_PORT NUMBER HYPHEN NUMBER
                        | DST_PORT NUMBER HYPHEN NUMBER TIMEOUT NUMBER
                        | DST_PORT NUMBER HYPHEN NUMBER TIMEOUT NEVER'''
    p_info['current_object'].append({'dst-port': Operator('RANGE', Port(p[2]), Port(p[4]))})


def p_opt_protocol_dst_2(p):
    '''opt_protocol_dst : empty'''


### protocol
def p_protocol(p):
    '''protocol : TCP
                | UDP
                | NUMBER'''
    p[0] = p[1]


## group

def p_group_line_1(p):
    '''group_line : SET GROUP ADDRESS item object_name opt_group_add opt_group_comment opt_hidden'''
    if p[5] not in object_dict:
        object_dict[p[5]] = []
    object_dict[p[5]] += p_info['current_object']
    p_info['current_object'] = []


def p_group_line_2(p):
    '''group_line : SET GROUP SERVICE object_name opt_group_add opt_group_comment opt_hidden'''
    if p[4] not in object_dict:
        object_dict[p[4]] = []
    object_dict[p[4]] += p_info['current_object']
    p_info['current_object'] = []


### opt_group_add
def p_opt_group_add_1(p):
    '''opt_group_add : ADD object_name'''
    p_info['current_object'].append({'object': p[2]})


def p_opt_group_add_2(p):
    '''opt_group_add : empty'''


def p_opt_group_comment(p):
    '''opt_group_comment : COMMENT items
                         | empty'''


def p_opt_hidden(p):
    '''opt_hidden : HIDDEN
                  | empty'''


# Interface parse

### interface_line
def p_interface_line_1(p):
    '''interface_line : SET INTERFACE object_name IP IP_ADDR SLASH NUMBER
                      | SET INTERFACE object_name IP IP_ADDR SLASH NUMBER SECONDARY'''
    # detect sub-interface
    if re.match(r'.*/.*\..*', p[3]):
        nameif = p[3].split('.')
        interface = p_info['firewall'].get_interface_by_nameif(nameif[0])
        if not interface:
            interface = Interface(nameif[0], None, None, [])
            p_info['firewall'].interfaces.append(interface)
        sub_if = interface.get_subif_by_nameif(p[3])
        if sub_if:
            sub_if.network = Ip(p[5], Ip.CidrToMask(int(p[7])))
        else:
            interface.sub_interfaces.append(Interface(p[3], Ip(p[5], Ip.CidrToMask(int(p[7]))), None, []))
    else:
        interface = p_info['firewall'].get_interface_by_nameif(p[3])
        if interface:
            interface.network = Ip(p[5], Ip.CidrToMask(int(p[7])))
        else:
            p_info['firewall'].interfaces.append(Interface(p[3], Ip(p[5], Ip.CidrToMask(int(p[7]))), None, []))


def p_interface_line_2(p):
    '''interface_line : SET INTERFACE object_name opt_tag ZONE object_name'''
    if re.match(r'.*/.*\..*', p[3]):
        nameif = p[3].split('.')
        interface = p_info['firewall'].get_interface_by_nameif(nameif[0])
        if not interface:
            interface = Interface(nameif[0], None, None, [])
            p_info['firewall'].interfaces.append(interface)
        sub_if = interface.get_subif_by_nameif(p[3])
        if sub_if:
            sub_if.name = p[6]
        else:
            sub_if = Interface(p[3], None, p[6], [])
            interface.sub_interfaces.append(sub_if)
        if p[4]:
            sub_if.attributes['tag'] = p[4]
    else:
        interface = p_info['firewall'].get_interface_by_nameif(p[3])
        if interface:
            interface.name = p[6]
        else:
            interface = Interface(p[3], None, p[6], [])
            p_info['firewall'].interfaces.append(interface)
        if p[4]:
            interface.attributes['tag'] = p[4]


def p_opt_tag_1(p):
    '''opt_tag : TAG NUMBER'''
    p[0] = p[2]

def p_opt_tag_2(p):
    '''opt_tag : empty'''


# Policy parse

## policy line

### policy_line
def p_policy_line_1(p):
    '''policy_line : SET POLICY opt_global opt_id opt_position opt_name opt_zone rules opt_nat action options
                   | SET POLICY DEFAULT_PERMIT_ALL'''
    insert_rule()


def p_policy_line_2(p):
    '''policy_line : SET POLICY MOVE NUMBER BEFORE NUMBER'''
    move_rule(int(p[4]), 'before', int(p[6]))


def p_policy_line_3(p):
    '''policy_line : SET POLICY MOVE NUMBER AFTER NUMBER'''
    move_rule(int(p[4]), 'after', int(p[6]))


def p_opt_global(p):
    '''opt_global : GLOBAL
                  | empty'''


### opt_id
def p_opt_id_1(p):
    '''opt_id : ID NUMBER'''
    p_info['current_policy'].identifier = int(p[2])


def p_opt_id_2(p):
    '''opt_id : empty'''


### opt_position
def p_opt_position_1(p):
    '''opt_position : TOP'''
    p_info['index_rule'] = 0


def p_opt_position_2(p):
    '''opt_position : BEFORE NUMBER'''
    for acl in p_info['firewall'].acl:
        for r in acl.rules:
            if r.identifier == int(p[2]):
                p_info['index_rule'] = acl.rules.index(r)


def p_opt_position_3(p):
    '''opt_position : empty'''


### opt_name
def p_opt_name_1(p):
    '''opt_name : NAME object_name'''
    p_info['current_policy'].name = p[2]


def p_opt_name_2(p):
    '''opt_name : empty'''


### opt_zone
def p_opt_zone_1(p):
    '''opt_zone : FROM object_name TO item'''
    p_info['policy_zone_src'] = remove_quote(p[2])
    p_info['policy_zone_dst'] = remove_quote(p[4])


def p_opt_zone_2(p):
    '''opt_zone : empty'''


### rules
def p_rules(p):
    '''rules : src_addr dst_addr svc_name'''


### src_addr
def p_src_addr_1(p):
    '''src_addr : object_name'''
    resolve(p[1], p_info['current_policy'], 'src')


def p_src_addr_2(p):
    '''src_addr : ANY'''
    p_info['current_policy'].ip_source = []


### dst_addr
def p_dst_addr_1(p):
    '''dst_addr : object_name'''
    resolve(p[1], p_info['current_policy'], 'dst')


def p_dst_addr_2(p):
    '''dst_addr : ANY'''
    p_info['current_policy'].ip_dest = []


### svc_name
def p_svc_name_1(p):
    '''svc_name : object_name'''
    resolve(p[1], p_info['current_policy'])


def p_svc_name_2(p):
    '''svc_name : ANY'''
    p_info['current_policy'].protocol = []
    p_info['current_policy'].port_source = []
    p_info['current_policy'].port_dest = []


### opt_nat
def p_opt_nat(p):
    '''opt_nat : NAT opt_src_nat opt_dst_nat
               | empty'''


### opt_src_nat
def p_opt_src_nat(p):
    '''opt_src_nat : SRC
                   | SRC DIP_ID NUMBER
                   | empty'''


### opt_dst_nat
def p_opt_dst_nat(p):
    '''opt_dst_nat : DST IP item
                   | DST IP item item
                   | DST IP item PORT item
                   | empty'''


### action
def p_action_1(p):
    '''action : DENY
              | REJECT'''
    p_info['current_policy'].action = Action(False)


def p_action_2(p):
    '''action : PERMIT'''
    p_info['current_policy'].action = Action(True)


def p_action_3(p):
    '''action : tunnel'''


### tunnel
def p_tunnel(p):
    '''tunnel : TUNNEL L2TP item
              | TUNNEL VPN_GROUP item
              | TUNNEL VPN item
              | TUNNEL VPN item L2TP item
              | TUNNEL VPN item PAIR_POLICY item'''
    raise Warning('Unsuported action')


### options
def p_options(p):
    '''options : items
               | empty'''


### policy_id_line
def p_policy_id_line_1(p):
    '''policy_id_line : SET POLICY opt_global ID NUMBER
                      | SET POLICY opt_global ID NUMBER APPLICATION options
                      | SET POLICY opt_global ID NUMBER ATTACK options
                      | SET POLICY opt_global ID NUMBER AV options'''
    p_info['context_policy'] = p_info['firewall'].get_rule_by_id(int(p[5]))


def p_policy_id_line_2(p):
    '''policy_id_line : SET POLICY opt_global ID NUMBER DISABLE'''
    p_info['firewall'].del_rule_by_id(int(p[5]))


### policy_context_line
def p_policy_context_line_1(p):
    '''policy_context_line : SET DST_ADDRESS object_name'''
    resolve(p[3], p_info['context_policy'], 'dst')


# TODO enable negate
def p_policy_context_line_2(p):
    '''policy_context_line : SET DST_ADDRESS NEGATE'''
    resolve(p[3], p_info['context_policy'], 'dst')


def p_policy_context_line_3(p):
    '''policy_context_line : SET SRC_ADDRESS object_name'''
    resolve(p[3], p_info['context_policy'], 'src')


# TODO enable negate
def p_policy_context_line_4(p):
    '''policy_context_line : SET SRC_ADDRESS NEGATE'''
    resolve(p[3], p_info['context_policy'], 'src')


def p_policy_context_line_5(p):
    '''policy_context_line : SET SERVICE object_name'''
    resolve(p[3], p_info['context_policy'])


def p_policy_context_line_6(p):
    '''policy_context_line : SET items'''


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
            s = raw_input('JuniperNetscreen > ')
        except EOFError:
            break
        if not s: continue
        print s
        result = parser.parse(s + '\n')
        print result

