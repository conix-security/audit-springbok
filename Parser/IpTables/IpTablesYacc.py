#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""iptables parser.
Each parser construct their firewall as they want,
but they must implement some function :
- init(name, raise_on_error=False)
- update():
- finish():
- get_firewall():
- show():
"""

from Parser.ply import yacc
from Parser.IpTables.IpTablesLex import tokens
from Parser.IpTables.IpTablesLex import lexer
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
from ROBDD.synthesis import compare
from ROBDD.operators import Bdd
import re
import ntpath


class ParseHook:
    def __init__(self):
        # Use for construct dictionary of object and object group
        self.parser = yacc.yacc()
        self.object_dict = {}

    def clear(self):
        self.parser = yacc.yacc()
        self.clear()

    def resolve(self, value):
        for k, v in self.object_dict.items():
            key = '$' + k
            if key in value:
                value = value.replace(key, v)
        return value

    def parse(self, line, parse_kit, debug=0):
        resolved_line = self.resolve(line)
        return self.parser.parse(resolved_line, parse_kit, debug)


# Use for detect state
p_info = {
    'firewall': Firewall(),
    'used_object': set(),
    'current_interface_name': None,
    'default_policy': dict(),
    'current_chain': None,
    'rule_id': 0,
    'rule_list': [],
    'rule_bind': dict(),
    'current_rule': Rule(None, None, [], [], [], [], [], Action(False)),
    'current_table': None,
    'raise_on_error': False,
}


def init(name, raise_on_error=False):
    # clear object variables
    parser.object_dict.clear()
    # init firewall
    p_info['firewall'] = Firewall()
    p_info['firewall'].name = name
    p_info['firewall'].hostname = ntpath.basename(name)
    p_info['firewall'].type = 'Iptables'
    # create default acl
    p_info['firewall'].acl.append(ACL('INPUT'))
    p_info['firewall'].acl.append(ACL('FORWARD'))
    p_info['firewall'].acl.append(ACL('OUTPUT'))
    # init parser state
    p_info['current_interface_name'] = None
    p_info['used_object'] = set()
    p_info['default_policy'] = dict()
    p_info['default_policy']['INPUT'] = Action(True)
    p_info['default_policy']['FORWARD'] = Action(True)
    p_info['default_policy']['OUTPUT'] = Action(True)
    p_info['current_chain'] = None
    p_info['rule_id'] = 0
    p_info['rule_list'] = []
    p_info['rule_bind'] = dict()
    p_info['current_rule'] = Rule(p_info['rule_id'], None, [], [], [], [], [], Action(False))
    p_info['rule_bind'][p_info['rule_id']] = [None, None]
    p_info['current_table'] = None
    # raise on error option
    p_info['raise_on_error'] = raise_on_error


def update():
    p_info['current_rule'] = Rule(p_info['rule_id'], None, [], [], [], [], [], Action(False))
    p_info['rule_bind'][p_info['rule_id']] = [None, None]


def finish():
    # apply default policy
    for k, v in p_info['default_policy'].items():
        for acl in p_info['firewall'].acl:
            if acl.name == k:
                acl.rules.append(Rule(-1, 'default', [], [], [], [], [], v))

    # bind ACLs
    # only INPUT, FORWARD and OUTPUT are concerned
    all_interfaces.list = []  # reset interfaces list
    acl_input = find_chain_by_name('INPUT')
    for rule in acl_input.rules:
        itf_in, _ = get_interface_list(rule.identifier)
        for itf in itf_in:
            get_acl(itf, p_info['firewall'], p_info['firewall'], 'INPUT').rules.append(rule)

    acl_forward = find_chain_by_name('FORWARD')
    for rule in acl_forward.rules:
        itf_in, itf_out = get_interface_list(rule.identifier)
        for itf1 in itf_in:
            for itf2 in itf_out:
                if itf1 is not itf2:
                    get_acl(itf1, itf2, p_info['firewall'], 'FORWARD').rules.append(rule)

    acl_output = find_chain_by_name('OUTPUT')
    for rule in acl_output.rules:
        _, itf_out = get_interface_list(rule.identifier)
        for itf in itf_out:
            get_acl(p_info['firewall'], itf, p_info['firewall'], 'OUTPUT').rules.append(rule)

    # detach not default ACL
    p_info['firewall'].acl = [a for a in p_info['firewall'].acl if a.name in ('INPUT', 'FORWARD', 'OUTPUT')]


def get_firewall():
    return [p_info['firewall']]


def show():
    print "--------- Object ---------"
    for k, v in parser.object_dict.items():
        print '%s :' % k
        for elem in v:
            for k1, v1 in elem.items():
                print '\t%s %s' % (k1, v1)
    print "--------- Firewall ---------"
    print "%s" % p_info['firewall'].to_string()


# create static list of all interfaces
def all_interfaces():
    if not all_interfaces.list:
        for i in p_info['firewall'].interfaces:
            if i.network:
                all_interfaces.list.append(i)
            for u in i.sub_interfaces:
                if u.network:
                    all_interfaces.list.append(u)
    return all_interfaces.list


all_interfaces.list = []


# get all interfaces concerned given the identifier rule
def get_interface_list(identifier):
    def _get_interface(itf):
        if itf:
            itf_name = itf.split('+')[0]
            return [i for i in p_info['firewall'].interfaces if i.name.startswith(itf_name)]
        else:
            return all_interfaces()

    if identifier not in p_info['rule_bind']:
        return _get_interface(None), _get_interface(None)

    itf_in, itf_out = p_info['rule_bind'][identifier]
    return _get_interface(itf_in), _get_interface(itf_out)


# get acl or create it
def get_acl(src, dst, firewall, name):
    source = src.network if isinstance(src, Interface) else src
    destination = dst.network if isinstance(dst, Interface) else dst
    acl = NetworkGraph.NetworkGraph.NetworkGraph().get_acl_list(source, destination, firewall)
    # create acl name distinction with interface name
    acl_name = name
    acl_name += ' ' if isinstance(src, Interface) or isinstance(dst, Interface) else ''
    acl_name += src.name if isinstance(src, Interface) else ''
    acl_name += '-' if isinstance(src, Interface) and isinstance(dst, Interface) else ''
    acl_name += dst.name if isinstance(dst, Interface) else ''
    for a in acl:
        if a.name == acl_name:
            return a

    # if no acl create it
    acl = ACL(acl_name)
    NetworkGraph.NetworkGraph.NetworkGraph().bind_acl(acl, firewall, src, dst)
    return acl


def remove_quote(name):
    if re.match(r'\".*\"', name):
        return name[1:-1]
    return name


def find_chain_by_name(name):
    for i in p_info['firewall'].acl:
        if i.name == name:
            return i
    raise Warning('ACL not found for this chain')


def delete_rule_by_spec(acl, rule):
    test = False

    for r in [a for a in acl.rules]:
        if compare(r.toBDD(), Bdd.BIIMPL, rule.toBDD()) <= 2 and r.action.chain == rule.action.chain:
            acl.rules.remove(r)
            test = True

    return test


def delete_rule_by_id(acl, id):
    return True if acl.rules.pop(id) else False


def flush_rules(acl):
    for a in p_info['firewall'].acl:
        if acl is None or a == acl:
            a.rules = []


def delete_chain(name):
    for acl in p_info['firewall'].acl:
        if acl.name in ('INPUT', 'OUTPUT', 'FORWARD'):
            pass
        else:
            if name is None or acl.name == name:
                p_info['firewall'].acl.remove(acl)


# remove all quote
def get_value(token):
    return remove_quote(token)


# 127.0.1.1/24, 192.168.0.1, ...
def to_ip_list(string):
    ip_list = []
    sub_list = string.split(',')

    for sub in sub_list:
        sub.split('/')
        mask = Ip.CidrToMask(sub[1]) if len(sub) > 1 else '255.255.255.255'
        ip_list.append(Ip(sub[0], mask))

    return ip_list


################ Parser ###############

def p_lines(p):
    '''lines : line
             | line lines'''


def p_line(p):
    '''line : interface_line NL
            | interface_address NL
            | variable_line NL
            | iptables_line NL
            | table_line NL
            | chain_line NL
            | command_line NL
            | WORD items NL
            | NL'''
    p[0] = p[1]


# Useful expression
def p_line_error(p):
    '''line : error NL'''


def p_empty(p):
    '''empty :'''
    pass


def p_items(p):
    '''items : item items
             | item'''


def p_item(p):
    '''item : WORD
            | NUMBER
            | COLON'''
    p[0] = p[1]


######## interface parse ########

# 'eth0      Link encap:Ethernet  HWaddr XX:XX:XX:XX:XX:XX'
def p_interface_line(p):
    '''interface_line : WORD LINK items'''
    p_info['current_interface_name'] = p[1]


# 'inet addr:192.168.0.1  Bcast:192.168.0.255  Mask:255.255.255.0'
def p_interface_address(p):
    '''interface_address : INET ADDR COLON IP_ADDR opt_bcast MASK COLON IP_ADDR'''
    ip_addr = Ip(p[4], p[8])
    p_info['firewall'].interfaces.append(Interface(p_info['current_interface_name'], ip_addr,
                                                   p_info['current_interface_name'], []))


def p_opt_bcast(p):
    '''opt_bcast : BCAST COLON IP_ADDR
                 | empty'''


######## variables ########

def p_variable_line_1(p):
    '''variable_line : WORD EQ item'''
    parser.object_dict[p[1]] = remove_quote(p[3])


# for key word (ex: IPT=iptables)
def p_variable_line_2(p):
    '''variable_line : WORD EQ error'''
    parser.object_dict[p[1]] = remove_quote(p[3].value)


######## iptables script ########

def p_iptables_line(p):
    '''iptables_line : IPTABLES opt_table commands'''


## table selection
def p_opt_table1(p):
    '''opt_table : TABLE FILTER
                 | empty'''
    p_info['current_table'] = 'filter'


def p_opt_table2(p):
    '''opt_table : TABLE NAT
                 | TABLE MANGLE
                 | TABLE RAW
                 | TABLE SECURITY'''
    raise Warning('Unsupported table')


######## iptables-save ########


def p_table_line1(p):
    '''table_line : STAR FILTER
                  | STAR NAT
                  | STAR MANGLE
                  | STAR RAW
                  | STAR SECURITY'''
    p_info['current_table'] = p[2]


def p_chain_line1(p):
    '''chain_line : COLON chain ACCEPT SQUARE_BRACKET NUMBER COLON NUMBER SQUARE_BRACKET'''
    if p_info['current_table'] == 'filter' and not find_chain_by_name(p[2]):
        p_info['firewall'].acl.append(ACL(p[2]))
        p_info['default_policy'][p[2]] = Action(True)


def p_chain_line2(p):
    '''chain_line : COLON chain DROP SQUARE_BRACKET NUMBER COLON NUMBER SQUARE_BRACKET'''
    if p_info['current_table'] == 'filter' and not find_chain_by_name(p[2]):
        p_info['firewall'].acl.append(ACL(p[2]))
        p_info['default_policy'][p[2]] = Action(False)


def p_chain_line3(p):
    '''chain_line : COLON chain WORD SQUARE_BRACKET NUMBER COLON NUMBER SQUARE_BRACKET'''
    if p_info['current_table'] == 'filter' and not find_chain_by_name(p[2]):
        p_info['firewall'].acl.append(ACL(p[2]))


def p_command_line(p):
    '''command_line : commands'''


######## command list ########


def p_statement(p):
    '''commands : append_cmd
                | check_cmd
                | delete_cmd
                | insert_cmd
                | replace_cmd
                | list_cmd
                | list_rules_cmd
                | flush_cmd
                | zero_cmd
                | new_chain_cmd
                | delete_chain_cmd
                | policy_cmd
                | rename_chain_cmd'''


def p_append_cmd(p):
    '''append_cmd : APPEND chain rule_spec'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        p_info['current_rule'].name = p[2]
        acl.rules.append(p_info['current_rule'])
        p_info['rule_id'] += 1


def p_check_cmd(p):
    '''check_cmd : CHECK chain rule_spec'''
    pass


def p_delete_cmd1(p):
    '''delete_cmd : DELETE chain rule_spec'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        delete_rule_by_spec(acl, p_info['current_rule'])


def p_delete_cmd2(p):
    '''delete_cmd : DELETE chain NUMBER'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        delete_rule_by_id(acl, int(p[3]) - 1)


def p_insert_cmd1(p):
    '''insert_cmd : INSERT chain NUMBER rule_spec'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        p_info['current_rule'].name = p[2]
        acl.rules.insert(int(p[3]) - 1, p_info['current_rule'])
        p_info['rule_id'] += 1


def p_insert_cmd2(p):
    '''insert_cmd : INSERT chain rule_spec'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        p_info['current_rule'].name = p[2]
        acl.rules.insert(0, p_info['current_rule'])
        p_info['rule_id'] += 1


def p_replace_cmd(p):
    '''replace_cmd : REPLACE chain NUMBER rule_spec'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        acl.rules[int(p[3]) - 1] = p_info['current_rule']


def p_list_cmd(p):
    '''list_cmd : LIST chain
                | LIST'''
    pass


def p_list_rules_cmd(p):
    '''list_rules_cmd : LIST_RULES chain
                      | LIST_RULES'''
    pass


def p_flush_cmd1(p):
    '''flush_cmd : FLUSH chain'''
    if p_info['current_table'] == 'filter':
        flush_rules(find_chain_by_name(p[2]))


def p_flush_cmd2(p):
    '''flush_cmd : FLUSH'''
    if p_info['current_table'] == 'filter':
        flush_rules(None)


def p_zero_cmd(p):
    '''zero_cmd : ZERO chain NUMBER
                | ZERO chain
                | ZERO'''


def p_new_chain_cmd(p):
    '''new_chain_cmd : NEW_CHAIN chain'''
    if p_info['current_table'] == 'filter':
        p_info['firewall'].acl.append(ACL(p[2]))


def p_delete_chain_cmd1(p):
    '''delete_chain_cmd : DELETE_CHAIN chain'''
    if p_info['current_table'] == 'filter':
        delete_chain(p[2])


def p_delete_chain_cmd2(p):
    '''delete_chain_cmd : DELETE_CHAIN'''
    if p_info['current_table'] == 'filter':
        delete_chain(None)


def p_policy_cmd(p):
    '''policy_cmd : POLICY chain target'''
    if p_info['current_table'] == 'filter':
        p_info['default_policy'][p[2]] = p[3]


def p_rename_chain_cmd(p):
    '''rename_chain_cmd : RENAME_CHAIN chain chain'''
    if p_info['current_table'] == 'filter':
        acl = find_chain_by_name(p[2])
        acl.name = p[3]
        for rule in acl.rules:
            rule.name = p[3]


def p_chain(p):
    '''chain : WORD'''
    p[0] = p[1]


def p_rule_spec(p):
    '''rule_spec : opt_matches'''


def p_opt_matches(p):
    '''opt_matches : opt_match opt_matches
                   | opt_match'''


def p_unsupported_option(p):
    '''unsupported_option : WORD unsupported_arguments
                          | WORD'''


def p_unsupported_arguments(p):
    '''unsupported_arguments : unsupported_arg unsupported_arguments
                             | unsupported_arg'''


def p_unsupported_arg(p):
    '''unsupported_arg : WORD
                       | NUMBER
                       | COLON'''


def p_opt_match(p):
    '''opt_match : IPV4
                 | IPV6
                 | protocol
                 | ip_source
                 | ip_destination
                 | port_source
                 | port_destination
                 | MATCH items
                 | jump_target
                 | goto_chain
                 | in_interface
                 | out_interface
                 | state_option
                 | error'''


def p_protocol_1(p):
    '''protocol : PROTOCOL item'''
    p_info['current_rule'].protocol.append(Operator('EQ', Protocol(get_value(p[2]))))


def p_protocol_2(p):
    '''protocol : BANG PROTOCOL item'''
    p_info['current_rule'].protocol.append(Operator('NEQ', Protocol(get_value(p[3]))))


def p_ip_source_1(p):
    '''ip_source : IP_SOURCE ip_addr_list'''
    for ip in p[2]:
        p_info['current_rule'].ip_source.append(Operator('EQ', ip))


def p_ip_source_2(p):
    '''ip_source : BANG IP_SOURCE ip_addr_list'''
    for ip in p[3]:
        p_info['current_rule'].ip_source.append(Operator('NEQ', ip))


def p_ip_dest_1(p):
    '''ip_destination : IP_DESTINATION ip_addr_list'''
    for ip in p[2]:
        p_info['current_rule'].ip_dest.append(Operator('EQ', ip))


def p_ip_dest_2(p):
    '''ip_destination : BANG IP_DESTINATION ip_addr_list'''
    for ip in p[3]:
        p_info['current_rule'].ip_dest.append(Operator('NEQ', ip))


def p_ip_addr_list1(p):
    '''ip_addr_list : ip_addr COMMA ip_addr_list'''
    p[0] = p[1] + p[3]


def p_ip_addr_list2(p):
    '''ip_addr_list : ip_addr'''
    p[0] = p[1]


def p_ip_addr1(p):
    '''ip_addr : IP_ADDR'''
    p[0] = [Ip(get_value(p[1]))]


def p_ip_addr2(p):
    '''ip_addr : IP_ADDR SLASH NUMBER'''
    p[0] = [Ip(p[1], Ip.CidrToMask(int(p[3])))]


def p_ip_addr3(p):
    '''ip_addr : IP_ADDR SLASH IP_ADDR'''
    p[0] = [Ip(p[1], p[3])]


def p_port_source_1(p):
    '''port_source : PORT_SOURCE port_list'''
    for v1, v2 in p[2]:
        if not v2:
            p_info['current_rule'].port_source.append(Operator('EQ', Port(v1)))
        else:
            p_info['current_rule'].port_source.append(Operator('RANGE', Port(v1), Port(v2)))


def p_port_source_2(p):
    '''port_source : BANG PORT_SOURCE port_list'''
    for v1, v2 in p[3]:
        if not v2:
            p_info['current_rule'].port_source.append(Operator('NEQ', Port(v1)))
        else:
            p_info['current_rule'].port_source.append(Operator('RANGE', Port(v1), Port(v2)).toggle())


def p_port_destination_1(p):
    '''port_destination : PORT_DESTINATION port_list'''
    for v1, v2 in p[2]:
        if not v2:
            p_info['current_rule'].port_dest.append(Operator('EQ', Port(v1)))
        else:
            p_info['current_rule'].port_dest.append(Operator('RANGE', Port(v1), Port(v2)))


def p_port_destination_2(p):
    '''port_destination : BANG PORT_DESTINATION port_list'''
    for v1, v2 in p[3]:
        if not v2:
            p_info['current_rule'].port_dest.append(Operator('NEQ', Port(v1)))
        else:
            p_info['current_rule'].port_dest.append(Operator('RANGE', Port(v1), Port(v2)).toggle())


def p_port_list1(p):
    '''port_list : item COLON item'''
    p[0] = [(get_value(p[1]), get_value(p[3]))]


def p_port_list2(p):
    '''port_list : item COMMA port_list'''
    p[0] = [(get_value(p[1]), None)] + p[3]


def p_port_list3(p):
    '''port_list : item'''
    p[0] = [(get_value(p[1]), None)]


def p_jump_target(p):
    '''jump_target : JUMP target'''
    p_info['current_rule'].action = p[2]


def p_goto_chain(p):
    '''goto_chain : GOTO chain'''
    p_info['current_rule'].action = Action(find_chain_by_name(p[2]), True)


def p_in_interface(p):
    '''in_interface : IN_INTERFACE WORD'''
    p_info['rule_bind'][p_info['rule_id']][0] = p[2]


def p_out_interface(p):
    '''out_interface : OUT_INTERFACE WORD'''
    p_info['rule_bind'][p_info['rule_id']][1] = p[2]


def p_state_option(p):
    '''state_option : STATE state_arg'''
    if not re.search('new', p[2], re.I):
        raise Warning('--state : ignore option')


def p_state_arg1(p):
    '''state_arg : WORD'''
    p[0] = p[1]


def p_state_arg2(p):
    '''state_arg : WORD COMMA state_arg'''
    p[0] = p[1] + p[3]


def p_target1(p):
    '''target : ACCEPT'''
    p[0] = Action(True)


def p_target2(p):
    '''target : DROP'''
    p[0] = Action(False)


def p_target3(p):
    '''target : QUEUE'''
    raise Warning('Unsupported target')


def p_target4(p):
    '''target : RETURN'''
    p[0] = Action('RETURN')


def p_target5(p):
    '''target : WORD'''
    if p_info['current_table'] == 'filter':
        p[0] = Action(find_chain_by_name(p[1]))


def p_error(p):
    if p_info['raise_on_error']:
        if p:
            print("Syntax error at '%s'" % p.value)
        else:
            print("Syntax error at EOF")
        raise SyntaxError


parser = ParseHook()

if __name__ == '__main__':
    while True:
        try:
            s = raw_input('iptables > ')
        except EOFError:
            break
        if not s: continue
        print s
        result = parser.parse(s + '\n')
        print result