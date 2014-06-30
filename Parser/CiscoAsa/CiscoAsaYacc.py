#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Cisco Asa parser.
Each parser construct their firewall as they want,
but they must implement some function :
- init(name, raise_on_error=False)
- update():
- finish():
- get_firewall():
- show():
"""

from Parser.ply import yacc
from Parser.CiscoAsa.CiscoAsaLex import tokens
from Parser.CiscoAsa.CiscoAsaLex import lexer
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
import CiscoAsaPort
import re
import ntpath


# Use for construct dictionary of object and object group
object_dict = {}

# Use for detect state
p_info = {
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
}


def init(name, raise_on_error=False):
    object_dict.clear()
    p_info['firewall'] = Firewall()
    p_info['firewall'].name = name
    p_info['firewall'].hostname = ntpath.basename(name)
    p_info['firewall'].type = 'Cisco Asa'
    p_info['interface_state'] = False
    p_info['current_interface'] = None
    p_info['object_name'] = None
    p_info['used_object'] = set()
    p_info['bounded_rules'] = set()
    p_info['rule_id'] = 0
    p_info['rule_list'] = []
    p_info['current_rule'] = Rule(None, None, [], [], [], [], [], Action(False))
    p_info['index_rule'] = 0
    p_info['global_rules'] = []
    p_info['raise_on_error'] = raise_on_error


def update():
    p_info['current_rule'] = Rule(None, None, [], [], [], [], [], False)
    p_info['index_rule'] = len(p_info['rule_list'])


def add_global_rules():
    for acl in p_info['firewall'].acl:
        for rule in p_info['global_rules']:
            acl.rules.append(rule)


def finish():
    # bind rule to acl
    for acl in p_info['firewall'].acl:
        for rule in p_info['rule_list']:
            if rule.name == acl.name:
                if rule.ip_source == 'INTERFACE':
                    rule.ip_source = NetworkGraph.NetworkGraph.NetworkGraph().get_interface_ip(acl)
                if rule.ip_dest == 'INTERFACE':
                    rule.ip_dest = NetworkGraph.NetworkGraph.NetworkGraph().get_interface_ip(acl)
                acl.rules.append(rule)

    add_global_rules()

    # add dictionary to firewall
    p_info['firewall'].dictionnary = dict(object_dict)

    # perform unused object and unbounded rules
    for k in object_dict:
        if k not in p_info['used_object']:
            p_info['firewall'].unused_objects.add(k)

    for rule in p_info['rule_list']:
        if rule.name not in p_info['bounded_rules']:
            p_info['firewall'].unbounded_rules.add(rule.name)


def get_firewall():
    return [p_info['firewall']]


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
            if k1 == 'network':
                if src_dest == 'src':
                    p_info['current_rule'].ip_source.append(v1)
                    p_info['current_rule'].ip_source_name.append(name)
                else:
                    p_info['current_rule'].ip_dest.append(v1)
                    p_info['current_rule'].ip_dest_name.append(name)
            elif k1 == 'protocol':
                p_info['current_rule'].protocol.append(v1)
                p_info['current_rule'].protocol_name.append(name)
            elif k1 == 'source':
                p_info['current_rule'].port_source.append(v1)
                p_info['current_rule'].port_source_name.append(name)
            elif k1 == 'destination':
                p_info['current_rule'].port_dest.append(v1)
                p_info['current_rule'].port_dest_name.append(name)
            if k1 == 'port':
                if src_dest == 'src':
                    p_info['current_rule'].port_source.append(v1)
                    p_info['current_rule'].port_source_name.append(name)
                else:
                    p_info['current_rule'].port_dest.append(v1)
                    p_info['current_rule'].port_dest_name.append(name)


precedence = (
    ('left', 'OBJECT_GROUP'),
)


def p_lines(p):
    '''lines : line
             | line lines'''
    if len(p) == 2:
        p[0] = p[1]
    else:
        p[0] = p[1] + '\n' + p[2]


def p_line(p):
    '''line : access_line NL
            | hostname_line NL
            | access_group_line NL
            | interface_line NL
            | ip_address_line NL
            | interface_name_line NL
            | object_line NL
            | network_line NL
            | service_line NL
            | object_group_line NL
            | group_object_line NL
            | icmp_object_line NL
            | network_object_line NL
            | protocol_object_line NL
            | port_object_line NL
            | service_object_line NL
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


# object parse

### object_line
def p_object_line_1(p):
    '''object_line : OBJECT NETWORK item
                   | OBJECT SERVICE item'''
    object_dict[p[3]] = []
    p_info['object_name'] = p[3]


def p_object_line_2(p):
    '''object_line : OBJECT NETWORK item RENAME item
                   | OBJECT SERVICE item RENAME item'''
    dict[p[5]] = object_dict.pop(p[3])
    p_info['object_name'] = p[5]


### network_line
def p_network_line_1(p):
    '''network_line : HOST IP_ADDR'''
    object_dict[p_info['object_name']].append({'network': Operator('EQ', Ip(p[2]))})


def p_network_line_2(p):
    '''network_line : NETWORK IP_ADDR'''
    object_dict[p_info['object_name']].append({'network': Operator('EQ', Ip(p[3], None, True))})


def p_network_line_3(p):
    '''network_line : OP_RANGE IP_ADDR IP_ADDR'''
    for i in range(Ip.toInteger(p[2]), Ip.toInteger(p[3]) + 1):
        object_dict[p_info['object_name']].append({'network': Operator('EQ', Ip(i, '255.255.255.255'))})


### service_line
def p_service_line_1(p):
    '''service_line : SERVICE item'''
    object_dict[p_info['object_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


def p_service_line_2(p):
    '''service_line : SERVICE tcp_udp opt_service'''
    object_dict[p_info['object_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})
    for i in p[3]:
        object_dict[p_info['object_name']].append(i)


def p_service_line_3(p):
    '''service_line : SERVICE ICMP optitem'''
    object_dict[p_info['object_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


def p_service_line_4(p):
    '''service_line : SERVICE ICMP6 optitem'''
    object_dict[p_info['object_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


### opt_service
def p_opt_service_1(p):
    '''opt_service : SOURCE operator'''
    p[2].v1 = Port(p[2].v1)
    if p[2].v2:
        p[2].v2 = Port(p[2].v2)
    p[0] = [{'source': p[2]}]


def p_opt_service_2(p):
    '''opt_service : DESTINATION operator'''
    p[2].v1 = Port(p[2].v1)
    if p[2].v2:
        p[2].v2 = Port(p[2].v2)
    p[0] = [{'destination': p[2]}]


def p_opt_service_3(p):
    '''opt_service : SOURCE operator DESTINATION operator'''
    res = []
    p[2].v1 = Port(p[2].v1)
    if p[2].v2:
        p[2].v2 = Port(p[2].v2)
    res.append({'source': p[2]})
    p[4].v1 = Port(p[4].v1)
    if p[4].v2:
        p[4].v2 = Port(p[4].v2)
    res.append({'destination': p[4]})
    p[0] = res


def p_opt_service_4(p):
    '''opt_service : empty'''
    p[0] = []


# object group parse

### object_group_line
def p_object_group_line_1(p):
    '''object_group_line : OBJECT_GROUP PROTOCOL item
                         | OBJECT_GROUP NETWORK item
                         | OBJECT_GROUP ICMP_TYPE item
                         | OBJECT_GROUP SECURITY item
                         | OBJECT_GROUP USER item'''
    object_dict[p[3]] = []
    p_info['object_group_name'] = p[3]


def p_object_group_line_2(p):
    '''object_group_line : OBJECT_GROUP SERVICE item object_opt_tcp_udp'''
    object_dict[p[3]] = []
    p_info['object_group_name'] = p[3]
    if p[4]:
        object_dict[p[3]].append({'protocol': Operator('EQ', Protocol(p[4]))})


### object_line
def p_group_object_line(p):
    '''group_object_line : GROUP_OBJECT item'''
    object_dict[p_info['object_group_name']].append({'object': p[2]})


### icmp_object_line
def p_icmp_object_line(p):
    '''icmp_object_line : ICMP_OBJECT item'''
    object_dict[p_info['object_group_name']].append({'protocol': Operator('EQ', Protocol('icmp'))})


### network_object_line
def p_network_object_line_1(p):
    '''network_object_line : NETWORK_OBJECT HOST IP_ADDR'''
    object_dict[p_info['object_group_name']].append({'network': Operator('EQ', Ip(p[3]))})


def p_network_object_line_2(p):
    '''network_object_line : NETWORK_OBJECT IP_ADDR IP_ADDR'''
    object_dict[p_info['object_group_name']].append({'network': Operator('EQ', Ip(p[2], p[3]))})


def p_network_object_line_3(p):
    '''network_object_line : NETWORK_OBJECT OBJECT item'''
    object_dict[p_info['object_group_name']].append({'object': p[3]})


### protocol_object_line
def p_protocol_object_line(p):
    '''protocol_object_line : PROTOCOL_OBJECT item'''
    object_dict[p_info['object_group_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


### port_object_line
def p_port_object_line_1(p):
    '''port_object_line : PORT_OBJECT OP_EQ item'''
    if p[3] in CiscoAsaPort.CiscoAsaPort:
        object_dict[p_info['object_group_name']].append({'port': Operator('EQ', Port(CiscoAsaPort.CiscoAsaPort[p[3]]))})
    else:
        object_dict[p_info['object_group_name']].append({'port': Operator('EQ', Port(p[3]))})


def p_port_object_line_2(p):
    '''port_object_line : PORT_OBJECT OP_RANGE NUMBER NUMBER'''
    object_dict[p_info['object_group_name']].append({'port': Operator('RANGE', Port(p[3]), Port(p[4]))})


### service_object_line
def p_service_object_line_1(p):
    '''service_object_line : SERVICE_OBJECT item'''
    object_dict[p_info['object_group_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


def p_service_object_line_2(p):
    '''service_object_line : SERVICE_OBJECT object_tcp_udp opt_service'''
    object_dict[p_info['object_group_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})
    for i in p[3]:
        object_dict[p_info['object_group_name']].append(i)


def p_service_object_line_3(p):
    '''service_object_line : SERVICE_OBJECT ICMP optitem'''
    object_dict[p_info['object_group_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


def p_service_object_line_4(p):
    '''service_object_line : SERVICE_OBJECT ICMP6 optitem'''
    object_dict[p_info['object_group_name']].append({'protocol': Operator('EQ', Protocol(p[2]))})


def p_service_object_line_5(p):
    '''service_object_line : SERVICE_OBJECT OBJECT item'''
    object_dict[p_info['object_group_name']].append({'object': p[3]})


### object_tcp_udp
def p_object_tcp_udp(p):
    '''object_tcp_udp : TCP
                      | UDP
                      | TCP_UDP'''
    p[0] = p[1]


### object_opt_tcp_udp
def p_object_opt_tcp_udp(p):
    '''object_opt_tcp_udp : TCP
                          | UDP
                          | TCP_UDP
                          | empty'''
    p[0] = p[1]


# interface parse

### interface_line
def p_interface_line(p):
    '''interface_line : INTERFACE item
                      | INTERFACE REDUNDANT item
                      | INTERFACE PORT_CHANNEL item
                      | BANG'''
    if p[1] == '!':
        p_info['interface_state'] = False
    else:
        p_info['interface_state'] = True
        # detect sub-interface
        if re.match(r'.*/.*\..*', p[len(p) - 1]):
            nameif = p[len(p) - 1].split('.')
            interface = p_info['firewall'].get_interface_by_nameif(nameif[0])
            if interface:
                interface.sub_interfaces.append(Interface(p[len(p) - 1], None, None, []))
                p_info['current_interface'] = interface.get_subif_by_nameif(p[len(p) - 1])
        else:
            p_info['firewall'].interfaces.append(Interface(p[len(p) - 1], None, None, []))
            p_info['current_interface'] = p_info['firewall'].get_interface_by_nameif(p[len(p) - 1])


# interface name parse

### interface_name_line
def p_interface_name_line(p):
    '''interface_name_line : NAMEIF item'''
    # detect sub-interface
    p_info['current_interface'].name = p[2]


# ip address parse

### ip_address_line
def p_ip_address_line_1(p):
    '''ip_address_line : IP ADDRESS IP_ADDR ip_address_option'''
    p_info['current_interface'].network = Ip(p[3], None, True)


def p_ip_address_line_2(p):
    '''ip_address_line : IP ADDRESS IP_ADDR IP_ADDR ip_address_option'''
    p_info['current_interface'].network = Ip(p[3], p[4])


def p_ip_address_line_3(p):
    '''ip_address_line : NO IP ADDRESS optitem'''


### ip_address_option
def p_ip_address_option(p):
    '''ip_address_option : STANDBY IP_ADDR
                         | CLUSTER_POOL item
                         | empty'''


# hostname

### hostname line
def p_hostname_line(p):
    '''hostname_line : HOSTNAME item'''
    p_info['firewall'].hostname = p[2]


# access-group parse

### access_group_line
def p_access_group_line_1(p):
    '''access_group_line : ACCESS_GROUP item IN INTERFACE item optitem
                         | ACCESS_GROUP item OUT INTERFACE item optitem'''
    interface = p_info['firewall'].get_interface_by_name(p[5])
    firewall = p_info['firewall']

    acl = firewall.get_acl_by_name(p[2])

    if not acl:
        acl = ACL(p[2])
        p_info['firewall'].acl.append(acl)
        p_info['bounded_rules'].add(p[2])
        NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(acl, firewall, interface, firewall)
        NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(acl, firewall, firewall, interface)


def p_access_group_line_2(p):
    '''access_group_line : ACCESS_GROUP item optitem'''
    p_info['bounded_rules'].add(p[2])
    for rule in p_info['rule_list']:
        if rule.name == p[2]:
            p_info['global_rules'].append(rule)


# access-list parse

### access_line
def p_access_line_1(p):
    '''access_line : ACCESS_LIST item line_number EXTENDED rule
                   | ACCESS_LIST item STANDARD line_number standard_rule'''
    p_info['current_rule'].identifier = p_info['rule_id']
    p_info['rule_id'] += 1
    p_info['current_rule'].name = p[2]
    p_info['rule_list'].insert(p_info['index_rule'], p_info['current_rule'])


def p_access_line_2(p):
    '''access_line : ACCESS_LIST item line_number REMARK words'''


### line_number
def p_line_number_1(p):
    '''line_number : WORD NUMBER'''
    p_info['index_rule'] = int(p[2])


def p_line_number_2(p):
    '''line_number : empty'''


### extended rule
def p_rule_1(p):
    '''rule : action protocol user_arg security_arg address_source security_arg address_dest log access_option'''


def p_rule_2(p):
    '''rule : action tcp_udp user_arg security_arg address_source port_source security_arg address_dest port_dest log access_option'''


def p_rule_3(p):
    '''rule : action ICMP user_arg security_arg address_source security_arg address_dest icmp_arg log access_option'''
    p_info['current_rule'].protocol.append(Operator('EQ', Protocol('icmp')))


### standard rule
def p_standard_rule_1(p):
    '''standard_rule : action ANY'''
    p_info['current_rule'].action = p[1]


def p_standard_rule_2(p):
    '''standard_rule : action HOST IP_ADDR'''
    p_info['current_rule'].action = p[1]
    p_info['current_rule'].ip_dest = [Operator('EQ', Ip(p[3]))]


def p_standard_rule_3(p):
    '''standard_rule : action IP_ADDR IP_ADDR'''
    p_info['current_rule'].action = p[1]
    p_info['current_rule'].ip_dest = [Operator('EQ', Ip(p[3], p[4]))]


### p_user_arg
def p_user_arg(p):
    '''user_arg : OBJECT_GROUP_USER item
                | USER item
                | USER ANY
                | USER NONE
                | USER_GROUP item
                | empty'''


### security_arg
def p_security_arg(p):
    '''security_arg : OBJECT_GROUP_SECURITY item
                    | SECURITY_GROUP NAME item
                    | SECURITY_GROUP TAG item
                    | empty'''


### log
def p_log(p):
    '''log : LOG
           | LOG item
           | LOG INTERVAL item
           | LOG item INTERVAL item
           | LOG DISABLE
           | LOG DEFAULT
           | empty'''


### access_option
def p_access_option(p):
    '''access_option : INACTIVE
                     | TIME_RANGE item
                     | empty'''


### action
def p_action_1(p):
    '''action : ACCEPT'''
    p_info['current_rule'].action = Action(True)


def p_action_2(p):
    '''action : DENY'''
    p_info['current_rule'].action = Action(False)


### tcp_udp
def p_tcp_udp_1(p):
    '''tcp_udp : TCP'''
    p_info['current_rule'].protocol.append(Operator('EQ', Protocol('tcp')))


def p_tcp_udp_2(p):
    '''tcp_udp : UDP'''
    p_info['current_rule'].protocol.append(Operator('EQ', Protocol('udp')))


### protocol
def p_protocol_1(p):
    '''protocol : item'''
    p_info['current_rule'].protocol.append(Operator('EQ', Protocol(p[1])))


def p_protocol_2(p):
    '''protocol : IP'''
    p_info['current_rule'].protocol = []


def p_protocol_3(p):
    '''protocol : OBJECT_GROUP item'''
    resolve(p[2])


def p_protocol_4(p):
    '''protocol : OBJECT item'''
    resolve(p[2])


### address_source
def p_address_source_1(p):
    '''address_source : HOST IP_ADDR'''
    p_info['current_rule'].ip_source.append(Operator('EQ', Ip(p[2])))


def p_address_source_2(p):
    '''address_source : IP_ADDR IP_ADDR'''
    p_info['current_rule'].ip_source.append(Operator('EQ', Ip(p[1], p[2])))


def p_address_source_3(p):
    '''address_source : ANY'''
    p_info['current_rule'].ip_source = []


def p_address_source_4(p):
    '''address_source : INTERFACE'''
    p_info['current_rule'].ip_source = 'INTERFACE'


def p_address_source_5(p):
    '''address_source : OBJECT_GROUP item'''
    resolve(p[2], 'src')


def p_address_source_6(p):
    '''address_source : OBJECT item'''
    resolve(p[2], 'src')


### address_dest
def p_address_dest_1(p):
    '''address_dest : HOST IP_ADDR'''
    p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(p[2])))


def p_address_dest_2(p):
    '''address_dest : IP_ADDR IP_ADDR'''
    p_info['current_rule'].ip_dest.append(Operator('EQ', Ip(p[1], p[2])))


def p_address_dest_3(p):
    '''address_dest : ANY'''
    p_info['current_rule'].ip_dest = []


def p_address_dest_4(p):
    '''address_dest : INTERFACE'''
    p_info['current_rule'].ip_dest = 'INTERFACE'


def p_address_dest_5(p):
    '''address_dest : OBJECT_GROUP item'''
    resolve(p[2], 'dest')


def p_address_dest_6(p):
    '''address_dest : OBJECT item'''
    resolve(p[2], 'dest')


### port_source
def p_port_source_1(p):
    '''port_source : operator'''
    p[1].v1 = Port(p[1].v1)
    if p[1].v2 is not None:
        p[1].v2 = Port(p[1].v2)
    p_info['current_rule'].port_source.append(p[1])


def p_port_source_2(p):
    '''port_source : OBJECT_GROUP item'''
    resolve(p[2], 'src')


def p_port_source_3(p):
    '''port_source : empty'''


### port_dest
def p_port_dest_1(p):
    '''port_dest : operator'''
    p[1].v1 = Port(p[1].v1)
    if p[1].v2 is not None:
        p[1].v2 = Port(p[1].v2)
    p_info['current_rule'].port_dest.append(p[1])


def p_port_dest_2(p):
    '''port_dest : OBJECT_GROUP item'''
    resolve(p[2], 'dest')


def p_port_dest_3(p):
    '''port_dest : empty'''


### icmp_arg
def p_icmp_arg(p):
    '''icmp_arg : item optitem
                | OBJECT_GROUP item
                | empty'''


### operator
def p_operator_1(p):
    '''operator : OP_LT port_service'''
    p[0] = Operator('LT', int(p[2]))


def p_operator_2(p):
    '''operator : OP_GT port_service'''
    p[0] = Operator('GT', int(p[2]))


def p_operator_3(p):
    '''operator : OP_EQ port_service'''
    p[0] = Operator('EQ', int(p[2]))


def p_operator_4(p):
    '''operator : OP_NEQ port_service'''
    p[0] = Operator('NEQ', int(p[2]))


def p_operator_5(p):
    '''operator : OP_RANGE port_service port_service'''
    p[0] = Operator('RANGE', int(p[2]), int(p[3]))


### port service
def p_port_service1(p):
    '''port_service : WORD'''
    p[0] = CiscoAsaPort.CiscoAsaPort[p[1]]


def p_port_service2(p):
    '''port_service : NUMBER'''
    p[0] = p[1]


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
            s = raw_input('CiscoAsa > ')
        except EOFError:
            break
        if not s: continue
        print s
        result = parser.parse(s + '\n')
        print result
