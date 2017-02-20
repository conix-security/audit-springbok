__author__ = 'maurice'

import ply.lex as lex
import ply.yacc as yacc
import re

from testLex import tokens
from testLex import lex
from socket import *
from socket import inet_ntoa
from struct import pack



i, j , k= 0, 0, 0

cptr = 0

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
rule_attr = ""
members = []
parsing_group_attr = False
parsing_rules = False
parsing_interfaces = False
parsing_a_rule = False
parsing_rule_arg = False
rules = []
parsing_exception = False
current_rule = {'name': None, 'action': None, 'src': [], 'dst': [], 'install': [], 'services': []}
services = {'udp', 'UDP', 'Udp', 'tcp', 'Tcp', 'TCP', 'other', 'Other','icmp', 'Icmp', 'igmp', 'Igmp',
                                       'Gre', 'gre', 'GRE', 'ospf', 'OSPF', 'Ospf',}
current_host = {'type': None, 'name' : None, 'ipaddr': None}


def init():
    pass


def finish():
    '''
    for rule in rules:
        print rule

    for o in object_dict:
        for k, v in o.iteritems():
            #print k, v
            if k == 'type' and (v in {'other', 'Other'}):
                pass
                #print o

    for rule in rules:
        # instantiate the rule Object here
        # _current_rule = Rule(...)
        if rule['services']:
            for s in rule['services']:
                r = resolve(s)
                if r['type'] in {'other', 'Other'}:
                    #create a Protocol object
                    #_current_rule['']
                    #
                    pass
                #print s, resolve(s)

    '''

    for o in object_dict:
        for k, v in o.iteritems():
            if k == 'type' and (v in {'gateway', 'gateway_cluster'}):
                pass
    all = []
    for rule in rules:
        if rule['src']:
            for s in rule['src']:
                all.append(resolve(s)['type'])

    all = set(all)
    pass

def get_firewall():
    pass

def resolve(name):
    found = False
    for obj in object_dict:
        if name in obj.values():
            found = True
            return obj
    if found == False :
        print name, 'Object not found !!!'
        #raise SyntaxError
    pass







def fromDotted2Dec(ipaddr):
    return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

def fromDec2Dotted(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))


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

z = 0


def update():
    global j
    j += 1

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


### words
def p_words_1(p):
    '''words : WORD'''
    p[0] = p[1]


def p_words_2(p):
    '''words : WORD words'''
    try:
        p[0] = p[1] + ' ' + p[2]
    except TypeError :
        pass




def p_begin_line(p) :
    '''begin_line : LPAREN'''
    global cptr
    cptr += 1


# parsing the begining of the file

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



# Parsing net obj

def p_begin_net_obj(p):
    '''begin_net_obj : COLON NETOBJ LPAREN'''
    global cptr, parsing_object_type
    parsing_object_type = "networks"
    print 'begining of parsing...', parsing_object_type
    cptr += 1



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
    pass


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
            print 'end of parsing...exception'

    elif cptr == 5:
        if p[4] in {'drop', 'accept'} and rule_attr == 'action':
            current_rule['action'] = p[4]
        else: current_iface['type'] = p[4]


def p_netmask_line(p):
    '''netmask_line : COLON NETMASK LPAREN IP_ADDR RPAREN'''
    global cptr, current_obj
    if cptr == 3 :
        current_obj['netmask'] = p[4]
    elif cptr == 5:
        current_iface['netmask'] = p[4]


# for machines ranges
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

# for interfaces

def p_interface_begin(p):
    '''interface_begin_line : COLON INTERFACES LPAREN'''
    global cptr, current_obj, current_fw, current_iface, parsing_interfaces
    if cptr == 3 :
        parsing_interfaces = True
    current_fw['name'] = current_obj['name']
    cptr += 1

def p_interface_index(p):
    '''interface_index : COLON IFINDEX LPAREN NUMBER RPAREN'''
    current_iface['index'] = p[4]

def p_interface_nameif(p):
    '''interface_nameif : COLON OFFICIALNAME LPAREN WORD RPAREN'''
    global current_iface
    current_iface['name'] = p[4]

# to parse services obj

def p_begin_servboj(p):
    '''servobj_begin_line : COLON SERVICES LPAREN'''
    global cptr, parsing_object_type, rule_attr
    if cptr == 1:
        parsing_object_type = "services"
    print 'begining of parsing...', parsing_object_type
    if cptr == 3 and parsing_object_type == 'rules':
        rule_attr = "services"
    cptr += 1



def p_service_port(p):
    '''service_port : COLON WORD LPAREN NUMBER RPAREN'''
    global parsing_object_type
    if parsing_object_type == 'services':
        if p[2] == 'port':
            current_obj['port'] = p[4]
        elif p[2] == 'protocol':
            current_obj['protocol'] = p[4]

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

# to parse sub objects and sub attributes

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
        print 'beginning of parsing...exception'
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


def p_attr_line(p):
    '''attr_line : COLON LPAREN WORD RPAREN
                 | COLON LPAREN RPAREN
                 | COLON LPAREN ANY RPAREN
                 | COLON OVERLAP_NAT_NETMASK LPAREN IP_ADDR RPAREN
                 | COLON LPAREN NUMBER WORD RPAREN
                 | COLON WORD LPAREN NUMBER WORD RPAREN
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


def p_end_obj(p):
    '''end_obj_line : RPAREN'''
    global cptr, current_obj, object_dict, current_fw, firewalls, parsing_group_attr, \
        parsing_object_type, current_rule, rules, services, parsing_interfaces, members, \
        rule_attr
    cptr -= 1
    #if parsing_object_type == 'rules' : print 'rulessssssssssssssssssssssssssssssssssssssssssssssssssss'
    if cptr == 2:
        try :
            if current_obj['type'] in {'host', 'network', 'machines_range', 'services', 'group', 'Group',
                                       'group_with_exclusion'}.union(services):
                object_dict.append(dict(current_obj))
                print current_obj

            elif current_obj['type'] in {'gateway_cluster', 'gateway'}:
                print current_obj
                current_fw = dict(current_obj)
                object_dict.append(dict(current_obj))
                current_fw['ifaces'] = list(current_ifaces)
                firewalls.append(dict(current_fw))


            #elif current_obj['type'] in {'group', 'Group'}:
        except KeyError:
                pass
        current_obj.clear()
        current_fw.clear()
        del current_ifaces[:]
        parsing_group_attr = False
        members = []
        if parsing_object_type == 'rules':
            rules.append(dict(current_rule))
            print current_rule
        current_rule.clear()
    elif cptr == 4:
        try:
            if parsing_interfaces == True:
                current_ifaces.append(dict(current_iface))
        except:
            pass
        current_iface.clear()
    elif cptr == 1:
        print 'end of parsing ', parsing_object_type
        parsing_object_type = ""
    elif cptr == 3:
        if parsing_interfaces == True :
            parsing_interfaces = False



# parsing rules

def p_begin_rules_line(p):
    '''begin_rules_line : COLON RULEBASE LPAREN WORD'''
    global cptr, current_rule, parsing_object_type, rule_attr
    cptr = 2
    parsing_object_type = 'rules'
    print 'begining of parsing...', parsing_object_type, '-->', p[4]
    if cptr == 2: pass

def p_new_rule_line(p):
    '''new_rule_line : COLON RULE LPAREN'''
    global parsing_a_rule, cptr, current_rule, rule_attr
    cptr += 1
    parsing_a_rule = True
    rule_attr = ''
    current_rule = {'name': None, 'action': None, 'src': [], 'dst': [], 'install': [], 'services': []}



def p_begin_action(p):
    '''begin_action : COLON ACTION LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "action"

def p_begin_dst(p):
    '''begin_dst : COLON DST LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "dst"

def p_begin_install(p):
    '''begin_install : COLON INSTALL LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "install"

def p_begin_src(p):
    '''begin_src : COLON SRC LPAREN'''
    global cptr, rule_attr
    cptr += 1
    rule_attr = "src"
    pass



def p_exception_line(p):
    '''exception_line : COLON EXCEPTION LPAREN REFERENCEOBJECT'''
    global parsing_exception
    parsing_exception = True


    global cptr
    cptr += 1



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


def p_error(p):
    #print "Syntax error in input!"
    pass
    #global b, f2
    #f2.write(b[-2000:])
    #f2.close
    print j
    raise SyntaxError
    #pass

__import__('os').system('rm pars*')

parser = yacc.yacc(optimize=1)

f = open("newObj.C", 'r')


while True :
    try :
        s = f.read()
    except EOFError :
        f.close()
        break
    if not s : continue
    result = parser.parse(s, debug=0)
    print  j, i, cptr
    #for fw in firewalls :
    #   pass
        #print fw
    #for il in object_dict :
    #   if 'MSN_Messenger_File_Transfer' in il.values() : print il
    finish()
    print resolve('Net_Pase_relais_entreprise')
    #for rule in rules : print rule
    #f2.close()
    #print len(hosts)
    #print hosts
    #for h in hosts :
    #   for k, v in h.iteritems() : print k, v
