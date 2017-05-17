from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Action import Action
from SpringBase.ACL import ACL
from SpringBase.Firewall import Firewall
from socket import inet_ntoa
from struct import pack
from Tools.ReduceRule import ReduceRule

class IptablesParser:
    instance = None

    def __init__(self, line=0):
        if not IptablesParser.instance:
            IptablesParser.instance = IptablesParser.__IptablesParser(line)
        elif line != 0:
            IptablesParser.instance.file_line = line

    class __IptablesParser:
        def __init__(self, line):
            self.link_table = {}
            self.all_tree = []
            self.identifier = 0
            self.rules = []
            self.all_blocks = []
            self.file_line = line
            self.fw = []
            self.filename = ""
            self.tmp_block = []

    def get_rule_from_iptable_line(self, rule_line):
        """
        get one iptable line and return a corresponding rule
        This function need some improvement in order to manage every case
        """
        action = Action(True) if rule_line[0] != "DROP" else Action(False)
        if rule_line[3] == "anywhere":
            ip_source = []
        else:
            if "/" not in rule_line[3]:
                ip_source = [Operator("EQ", Ip(rule_line[3]))]
            else:
                ip_source = [Operator('EQ', Ip(rule_line[3].split('/')[0], fromDec2Dotted(int(rule_line[3].split('/')[1]))))]
        if rule_line[4] == "anywhere":
            ip_dest = []
        else:
            if "/" not in rule_line[4]:
                ip_dest = [Operator("EQ", Ip(rule_line[4]))]
            else:
                ip_dest = [Operator('EQ', Ip(rule_line[4].split('/')[0], fromDec2Dotted(int(rule_line[4].split('/')[1]))))]
        port_source = []
        port_dest = []
        protocol = [] if rule_line[1] == "all" else [Operator("EQ", Protocol(rule_line[1]))]
        if len(rule_line) >= 7:
            if "spt" in rule_line[6]:
                port_source.append(Operator("EQ", Port(rule_line[6][4:-1])))
            elif "dpt" in rule_line[6]:
                port_dest.append(Operator("EQ", Port(rule_line[6][4:-1])))
            elif "multiport" in rule_line:
                tmp_idx = rule_line.index("multiport")
                if rule_line[tmp_idx+1] == "dports":
                    ports_dest_list = rule_line[tmp_idx+2].split(",")
                    for tmp_port_dest in ports_dest_list:
                        port_dest.append(Operator("EQ", Port(tmp_port_dest)))
            else:
                tmp_line = ""
                for tmp_elem in rule_line:
                    tmp_line += "  " + tmp_elem
                print tmp_line
        return Rule(0, "", protocol, ip_source, port_source, ip_dest, port_dest, action)

    def merge_protocol(self, protocols_list):
        """
        return a list of protocol with all common element present in each list of protocols
        """
        len_protocols_list = len(protocols_list)
        for idx, protocols in enumerate(protocols_list):
            if idx + 1 <= len_protocols_list - 1:
                tmp_list = []
                if len(protocols_list[idx]) == 0:
                    continue
                elif len(protocols_list[idx+1]) == 0:
                    protocols_list[idx+1] = protocols_list[idx]
                    continue
                for protocol1 in protocols_list[idx]:
                    for protocol2 in protocols_list[idx + 1]:
                        if protocol1.operator == "EQ" and protocol2.operator == "EQ":
                            if protocol1.v1.protocol == protocol2.v1.protocol:
                                tmp_list.append(protocol1)
                                break
                protocols_list[idx+1] = tmp_list
                if len(tmp_list) == 0:
                    protocols_list[len(protocols_list) - 1] = None
                    break
        return protocols_list[len(protocols_list) - 1]

    def merge_port(self, ports_list):
        """
        return a list with all common element present in each list of port
        """
        len_ports_list = len(ports_list)
        for idx, ports in enumerate(ports_list):
            if idx + 1 <= len_ports_list - 1:
                if len(ports_list[idx]) == 0:
                    continue
                elif len(ports_list[idx+1]) == 0:
                    ports_list[idx+1] = ports_list[idx]
                    continue
                tmp_list = []
                for port1 in ports_list[idx]:
                    for port2 in ports_list[idx + 1]:
                        if port1.operator == "EQ" and port2.operator == "EQ":
                            if port1.v1.port == port2.v1.port:
                                tmp_list.append(port1)
                                break
                        elif port1.operator == "RANGE" and port2.operator == "EQ":
                            if port1.v1.port < port2.v1.port < port1.v2.port:
                                tmp_list.append(port2)
                        elif port1.operator == "EQ" and port2.operator == "RANGE":
                            if port2.v1.port < port1.v1.port < port2.v2.port:
                                tmp_list.append(port1)
                        elif port1.operator == "RANGE" and port2.operator == "RANGE":
                            p1v1 = port1.v1.port
                            p1v2 = port1.v2.port
                            p2v1 = port2.v1.port
                            p2v2 = port2.v2.port
                            if p1v1 < p2v1 < p1v2 and p1v1 < p2v2 < p1v2:
                                tmp_list.append(port2)
                            elif p1v1 < p2v1 < p1v2 and p1v2 < p2v2:
                                tmp_list.append(Operator("RANGE", Port(p2v1), Port(p1v2)))
                            elif p2v1 < p1v1 and p1v1 < p2v2 < p1v2:
                                tmp_list.append(Operator("RANGE", Port(p1v1), Port(p2v2)))
                            elif p2v1 < p1v1 < p2v2 and p2v1 < p1v2 < p2v2:
                                tmp_list.append(port1)
                ports_list[idx + 1] = tmp_list
                if len(tmp_list) == 0:
                    ports_list[len(ports_list) - 1] = None
                    break
        return ports_list[len(ports_list) - 1]

    def merge_ip(self, ips_list):
        """
        return a list with all common element present in each list of ip
        """
        len_ips_list = len(ips_list)
        for idx, tmp_ip in enumerate(ips_list):
            if idx + 1 <= len_ips_list - 1:
                tmp_list = []
                if len(ips_list[idx]) == 0:
                    continue
                elif len(ips_list[idx+1]) == 0:
                    ips_list[idx+1] = ips_list[idx]
                    continue
                for ip1 in ips_list[idx]:
                    for ip2 in ips_list[idx + 1]:
                        # 4294967295 value for 255.255.255.255
                        if ip1.v1.mask != 4294967295:
                            tmp_val = 4294967295
                            ip_min_check = ip1.v1.ip & ip1.v1.mask
                            tmp_val = tmp_val ^ ip1.v1.mask
                            ip_max_check = ip1.v1.ip | tmp_val
                            ip1 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
                        if ip2.v1.mask != 4294967295:
                            tmp_val = 4294967295
                            ip_min_check = ip2.v1.ip & ip2.v1.mask
                            tmp_val = tmp_val ^ ip2.v1.mask
                            ip_max_check = ip2.v1.ip | tmp_val
                            ip2 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
                        if ip1.operator == "EQ" and ip2.operator == "EQ":
                            if ip1.v1.ip == ip2.v1.ip:
                                tmp_list.append(ip1)
                                break
                        elif ip1.operator == "RANGE" and ip2.operator == "EQ":
                            if ip1.v1.ip < ip2.v1.ip < ip1.v2.ip:
                                tmp_list.append(ip2)
                        elif ip1.operator == "EQ" and ip2.operator == "RANGE":
                            if ip2.v1.ip < ip1.v1.ip < ip2.v2.ip:
                                tmp_list.append(ip1)
                        elif ip1.operator == "RANGE" and ip2.operator == "RANGE":
                            if ip1.v1.ip < ip2.v1.ip < ip1.v2.ip and ip1.v1.ip < ip2.v2.ip < ip1.v2.ip:
                                tmp_list.append(ip2)
                            elif ip1.v1.ip < ip2.v1.ip < ip1.v2.ip and ip1.v2.ip < ip2.v2.ip:
                                tmp_list.append(Operator("RANGE", Ip(ip2.v1.ip), Ip(ip1.v2.ip)))
                            elif ip2.v1.ip < ip1.v1.ip and ip1.v1.ip < ip2.v2.ip < ip1.v2.ip:
                                tmp_list.append(Operator("RANGE", Ip(ip1.v1.ip), Ip(ip2.v2.ip)))
                            elif ip2.v1.ip < ip1.v1.ip < ip2.v2.ip and ip2.v1.ip < ip1.v2.ip < ip2.v2.ip:
                                tmp_list.append(ip1)
                ips_list[idx + 1] = tmp_list
                if len(tmp_list) == 0:
                    ips_list[len(ips_list) - 1] = None
                    break
        return ips_list[len(ips_list) - 1]

    def merge_rules(self, list_rules):
        """
        merge a list of rule into a unique rule compose with all the common element
        of each rules
        """
        protocol_list = []
        port_source_list = []
        port_dest_list = []
        ip_source_list = []
        ip_dest_list = []
        action_list = []

        # collect data
        for rule in list_rules:
            protocol_list.append(rule.protocol)
            port_source_list.append(rule.port_source)
            ip_source_list.append(rule.ip_source)
            port_dest_list.append(rule.port_dest)
            ip_dest_list.append(rule.ip_dest)
            action_list.append(rule.action)

        # merge all data
        protocol_list = self.merge_protocol(protocol_list)
        port_source_list = self.merge_port(port_source_list)
        port_dest_list = self.merge_port(port_dest_list)
        ip_source_list = self.merge_ip(ip_source_list)
        ip_dest_list = self.merge_ip(ip_dest_list)

        if protocol_list is None \
                or port_source_list is None \
                or port_dest_list is None \
                or ip_source_list is None \
                or ip_dest_list is None:
            print "Error merging iptables rules"
            tmp_error = "protocol : OK\n" if protocol_list is None else "protocol : Error\n"
            tmp_error += "port source : OK\n" if port_source_list is None else "port source : Error\n"
            tmp_error += "port dest : OK\n" if port_dest_list is None else "port dest : Error\n"
            tmp_error += "ip source : OK\n" if ip_source_list is None else "ip source : Error\n"
            tmp_error += "ip dest : OK\n" if ip_dest_list is None else "ip dest : Error\n"
            print tmp_error

            return None
        # create a new rule
        rule = Rule(self.instance.identifier, "", protocol_list,
                    ip_source_list,
                    port_source_list,
                    ip_dest_list,
                    port_dest_list,
                    action_list[len(action_list)-1])
        self.instance.identifier += 1
        return rule

    def get_rules_from_path_list(self, path_list):
        """
        return a set of rules correspondig to the path list
        """
        rule_list = []
        for path in path_list:
            tmp_rule_list = []
            for data in path:
                tmp_rule_list.append(self.get_rule_from_iptable_line(data))
            tmp_data = self.merge_rules(tmp_rule_list)
            rule_list.append(tmp_data)
        rule_list = ReduceRule().reduce_rule(rule_list)
        return rule_list

    def get_node(self, node_name):
        """
        return the node which name is node_name
        """
        node = None
        for item in self.instance.all_tree:
            if item.name == node_name:
                node = item
                break
        return node

    def create_all_path_from_node(self, node):
        """
        create all path from a node of the tree
        """
        path_list = []
        current_path = []
        for idx, component in enumerate(node.data_list):
            if idx >= 2:
                if component[0] != "ACCEPT" and component[0] != "DROP":
                    new_node = self.get_node(component[0])
                    if new_node is not None:
                        path_list_from_node = self.create_all_path_from_node(new_node)
                        for path in path_list_from_node:
                            path.insert(0, component)
                            path_list.append(path)
                else:
                    tmp = list(current_path)
                    tmp.append(component)
                    path_list.append(tmp)
        return path_list

    def create_block_from_file(self, content):
        """
        split the iptables files into blocks
        """
        if content == "\n":
            self.instance.all_blocks.append(self.instance.tmp_block)
            self.instance.tmp_block = []
        else:
            data = content.split(" ")
            data = [i for i in data if i != ""]
            self.instance.tmp_block.append(data)

    def complete_all_tree(self):
        """
        add a node to the tree for each blocks
        """
        for block in self.instance.all_blocks:
            new_node = IptablesNode(block[0][1])
            for idx, component in enumerate(block):
                if idx >= 2:
                    new_node.data_list = block
                    if component[0] != "ACCEPT" and component != "DROP":
                        if component[0] in self.instance.link_table.keys():
                            if block[0][1] not in self.instance.link_table[component[0]]:
                                self.instance.link_table[component[0]] = self.instance.link_table[component[0]] + " " + block[0][1]
                        else:
                            self.instance.link_table[component[0]] = block[0][1]
            self.instance.all_tree.append(new_node)

    def get_general_rule(self, node):
        """
        Return a rule in accords with the policy
        """
        rule = None
        txt = node.data_list[0][2]+ " " +node.data_list[0][3]
        if txt == "(policy DROP)\n":
            rule = Rule(self.instance.identifier, "all", [], [], [], [], [], Action(False))
            self.instance.identifier += 1
        elif txt == "(policy ACCEPT)\n":
            rule = Rule(self.instance.identifier, "all", [], [], [], [], [], Action(False))
            self.instance.identifier += 1
        return rule

    def parse(self, line, test = 0, debug=0):
        self.instance.identifier += 1
        self.create_block_from_file(line)
        if self.instance.identifier == self.instance.file_line:
            self.instance.all_blocks.append(self.instance.tmp_block)
            self.complete_all_tree()
            self.instance.identifier = 0

    def parse_nat(self, line, test=0, debug=0):
        self.instance.identifier += 1
        self.create_block_from_file(line)
        if self.instance.identifier == self.instance.file_line:
            self.instance.all_blocks.append(self.instance.tmp_block)
            self.complete_all_tree_nat()

    def complete_all_tree_nat(self):
        """
        add a node to the tree for each blocks
        """
        for block in self.instance.all_blocks:
            if block[0][1] == 'PREROUTING' or block[0][1] == 'POSTROUTING' or 'MASQUERADING':
                new_node = IptablesNode(block[0][1])
                for idx, component in enumerate(block):
                    for data in component:
                        if data == "DNAT" or data == "SNAT":
                            self.data_nat_to_nat_rule(0, component)
                            break
                        elif data == "MASQUERADE":
                            self.data_nat_to_nat_rule(1, component)
                            break
                self.instance.all_tree.append(new_node)

    def data_nat_to_nat_rule(self, opt_nat, line):
        # case SNAT/DNAT
        if opt_nat == 0:
            print "SNAT/DNAT"
        elif opt_nat == 1:
            print "MASQUERADING"
            for data in line:
                print data


class IptablesNode(object):
    def __init__(self, name):
        self.data_list = []
        self.name = name
        self.related_node_name = []
        self.related_node = []


def fromDec2Dotted(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))


parser = IptablesParser()
lexer = None


def file_len(fname):
    """Return the number of line in the file"""
    i = 0
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def init(fname, check=False):
    if not check:
        my_parse = IptablesParser()
        my_parse.instance.link_table = {}
        my_parse.instance.all_tree = []
        my_parse.instance.identifier = 0
        my_parse.instance.rules = []
        my_parse.instance.all_blocks = []
        my_parse.instance.file_line = 0
        my_parse.instance.fw = []
        my_parse.instance.filename = ""
        my_parse.instance.tmp_block = []
        my_parse = IptablesParser(file_len(fname))
        my_parse.instance.filename = fname

def update():
    pass


def finish():
    my_parser = IptablesParser()
    # select the 3 main nodes
    input_node = my_parser.get_node("INPUT")
    output_node = my_parser.get_node("OUTPUT")
    forward_node = my_parser.get_node("FORWARD")

    # create every path from the 3 nodes
    input_path_list = my_parser.create_all_path_from_node(input_node)
    output_path_list = my_parser.create_all_path_from_node(output_node)
    forward_path_list = my_parser.create_all_path_from_node(forward_node)

    # create the rules which correspond to the path list
    input_rules = my_parser.get_rules_from_path_list(input_path_list)
    output_rules = my_parser.get_rules_from_path_list(output_path_list)
    forward_rules = my_parser.get_rules_from_path_list(forward_path_list)

    # add the rule for default drop or accept
    input_rules.append(my_parser.get_general_rule(input_node))
    output_rules.append(my_parser.get_general_rule(output_node))
    forward_rules.append(my_parser.get_general_rule(forward_node))

    # create the fw
    acl_input = ACL("INPUT")
    acl_input.rules = input_rules
    acl_output = ACL("OUTPUT")
    acl_output.rules = output_rules
    acl_forward = ACL("FORWARD")
    acl_forward.rules = forward_rules
    new_fw = Firewall()
    new_fw.acl = [acl_input, acl_output, acl_forward]
    new_fw.hostname = my_parser.instance.filename
    new_fw.name = my_parser.instance.filename
    new_fw.type = "Iptables"
    my_parser.instance.fw.append(new_fw)

def get_firewall():
    my_parser = IptablesParser()
    fw = my_parser.instance.fw
    my_parser.instance = None
    return fw


def show():
    pass

"""
fname = "iptables01.txt"
fw = IptablesParser().parse(fname)
"""

"""
 init(name, raise_on_error=False)
- update():
- finish():
- get_firewall():
- show():
"""