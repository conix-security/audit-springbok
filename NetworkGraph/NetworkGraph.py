#! /usr/bin/env python
# -*- coding: utf-8 -*-

import networkx as nx
from Node import *
from Edge import *
from SpringBase.Operator import Operator
from SpringBase.Ip import Ip
from SpringBase.Rule import Rule
from SpringBase.Port import Port
from SpringBase.Protocol import Protocol
from SpringBase.Action import Action
from SpringBase.Interface import Interface




######## Modification of the class by Maurice TCHAMGOUE N. on 22-06-2015
###          * Adding _new_get_all_simple_paths and __new_all_simple_paths methods :
###            these methods are intends to replace the old algorithm used by
###            query path



class NetworkGraph(object):
    """NetworkGraph class.
    The NetworkGraph class use singleton pattern.
    It contains all necessary information of the project (i.e. firewall list).
    It use networkX to construct the topology graph.

    Parameters
    ----------
    firewalls : Firewall list. A list of firewall.
    graph : networkX graph. A network graph used for topology.
    multidigraph : networkX multidigraph. A network multidigraph used for ACL interconnections.
    subnet_list : Ip list. A list of network used for firewalls interconnections
    digraph_subnet_list : Ip list. A list of network used for ACL interconnections
    node_click : bool. True if a node is clicked, False otherwise
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(NetworkGraph, cls).__new__(cls, *args, **kwargs)
            cls._instance.firewalls = []
            cls._instance.graph = nx.Graph()
            cls._instance.multidigraph = nx.MultiDiGraph()
            cls._instance.subnet_list = []
            cls._instance.digraph_subnet_list = []
            cls._instance.node_click = False
            cls._instance.show_fw = False
            cls._instance.show_network = False
        return cls._instance

    # Parse firewall and construct the network topology
    def network_graph(self, firewall):
        """This method construct/update the graph.
        This method should be call each time a new firewall is added.

        Parameters
        ----------
        firewall : Firewall. The new firewall to add
        """
        self.firewalls.append(firewall)
        self.graph.add_node(firewall, object=Node(firewall))

        for i in firewall.interfaces:
            self._add_interface(firewall, i)
            for sub_if in i.sub_interfaces:
                self._add_interface(firewall, sub_if)
        print len(self.graph.edges()), self.graph.edges()

    def _add_interface(self, firewall, interface):
        """Find or add the network interface if it doesn't exist and link the network with firewall

        Parameters
        ----------
        firewall : Firewall. The firewall to connect.
        interface : Interface. The interface to find / add.
        """
        if interface.network:
            res = Ip.ListContains(self.subnet_list, interface.network)
            if res is None:
                self.subnet_list.append(interface.network)
                self.graph.add_node(interface.network, object=Node(interface.network))
                self.graph.add_edge(firewall, interface.network, object=Edge(interface, firewall))
            else:
                self.graph.add_edge(firewall, res, object=Edge(interface, firewall))

    def _add_route_info(self, firewall, data, interface, edge):
        """Add informations about gateways and destinations network, and link them with the corresponding
           firewall and network.
        """
        self.graph.add_node(data, object=Node(data))
        self.graph.add_edge(firewall, data, object=Edge(data, firewall))
        self.graph.add_edge(data, interface.network, object=Edge(data, interface))


    def bind_acl(self, acl, firewall, ip1, ip2):
        """Find or add nodes ip1 and ip2 if they don't exist and link them with the firewall and the acl as attribute

        Parameters
        ----------
        acl : ACL. The acl to bind
        firewall : Firewall. The firewall to of the ACL.
        ip1/2 : Interface or Firewall. The nodes to find / add
        """
        def add_node(obj):
            if isinstance(obj, Interface) and obj.network:
                res = Ip.ListContains(self.digraph_subnet_list, obj.network)
                if res is None:
                    self.digraph_subnet_list.append(obj.network)
                    self.multidigraph.add_node(obj.network)
                    return obj.network
                else:
                    return res
            else:
                self.multidigraph.add_node(obj)
                return obj

        res1 = add_node(ip1)
        res2 = add_node(ip2)
        self.multidigraph.add_edge(res1, res2, key=firewall, firewall=firewall, acl=acl)

    def remove_firewall(self, node):
        """Remove the firewall and clean all his elements.

        Parameters
        ----------
        node : Node. The firewall node.
        """
        self.firewalls.remove(node.object)
        for edge in self.graph.edge[node.object].items():
            edge[1]['object'].remove()

        for edge in self.multidigraph.edges(data=True):
            if edge[2]['firewall'] == node.object:
                self.multidigraph.remove_edge(edge[0], edge[1], key=node.object)

        self.graph.remove_node(node.object)
        node.remove()
        for node in self.graph.node.items():
            if self.graph.degree(node[0]) == 0:
                node[1]['object'].remove()
                self.graph.remove_node(node[0])
                if isinstance(node[0], Ip):
                    self.subnet_list.remove(node[0])

        for node in self.multidigraph.node.items():
            if self.multidigraph.degree(node[0]) == 0:
                self.multidigraph.remove_node(node[0])
                if isinstance(node[0], Ip):
                    self.digraph_subnet_list.remove(node[0])

    def layout_graph(self):
        """Set node and edge position using spring layout"""
        pos = nx.drawing.spring_layout(self.graph)

        for node in self.graph.nodes():
            self.graph.node[node]['object'].x, self.graph.node[node]['object'].y = pos[node]

        for edge in self.graph.edges():
            self.graph.edge[edge[0]][edge[1]]['object'].x = [pos[edge[0]][0], pos[edge[1]][0]]
            self.graph.edge[edge[0]][edge[1]]['object'].y = [pos[edge[0]][1], pos[edge[1]][1]]

    def get_reversed_multidigraph(self):
        reversed = nx.MultiDiGraph()
        reversed.add_nodes_from(self.multidigraph.nodes())
        reversed.add_edges_from([(e2, e1) for e1, e2 in self.multidigraph.edges()])
        return reversed

    def get_all_simple_path(self, source, dest):
        """Get all simple path from a point to an other.

        Return
        ------
        Return a networkX list of path
        """
        source_node = None
        dest_node = None

        if source:
            for i in self.subnet_list:
                if Ip.ListContains([i], source):
                    source_node = i
                    break

        if dest:
            for i in self.subnet_list:
                if Ip.ListContains([i], dest):
                    dest_node = i
                    break

        if not source or not dest:
            for node in self.graph.nodes(data=True):
                if node[1]['object'].marker_type == 'from':
                    source_node = node[0]
                if node[1]['object'].marker_type == 'to':
                    dest_node = node[0]

        if not source_node or not self.multidigraph.has_node(source_node)\
                or not dest_node or not self.multidigraph.has_node(dest_node):
            raise

        self._new_get_all_simple_paths(source_node, dest_node)
        return self.res

        # return nx.all_simple_paths(self.multidigraph, source_node, dest_node)

    def get_all_simple_path_new(self, rule, current_path, ip_dest_final):
        path_list = []

        data_list = self.get_reachable_ip(rule, current_path)
        for data in data_list:
            tmp = list(current_path)
            tmp.append(data[1])
            if self.ip_operator_compare(data[1][1], ip_dest_final):
                path_list.append(tmp)
            else:
                tmp_list = self.get_all_simple_path_new(data[0], tmp, ip_dest_final)
                path_list = path_list + tmp_list
        return path_list

    def get_reachable_ip(self, rule, current_path):
        data = []
        for fw in self.firewalls:
            for acl in fw.acl:
                for current_rule in acl.rules:
                    if current_rule.action.chain == rule.action.chain and current_rule.action.goto == rule.action.goto:
                        port_source_list = self.regular_list_compare_operator(rule.port_source, current_rule.port_source)
                        port_dest_list = self.regular_list_compare_operator(rule.port_dest, current_rule.port_dest)
                        protocol_list = self.regular_list_compare_operator(rule.protocol, current_rule.protocol)
                        if (port_source_list is not None) \
                                and (port_dest_list is not None) \
                                and (protocol_list is not None):

                            check_ip = False
                            for ip_ope in current_rule.ip_source:
                                if self.ip_operator_compare(ip_ope, rule.ip_source[0]):
                                    check_ip = True
                            if check_ip:
                                for operator in current_rule.ip_dest:
                                    check_op = True
                                    for current_op in current_path:
                                        if current_op[1].v1.ip == operator.v1.ip and current_op[1].v1.mask == operator.v1.mask:
                                            check_op = False
                                    if check_op:
                                        for tmp_data in data:
                                            if tmp_data[1][0] == fw.hostname and tmp_data[1][1].v1.ip == operator.v1.ip and \
                                                            tmp_data[1][1].v1.mask == operator.v1.mask:
                                                check_op = False
                                        if check_op:
                                            tmp_struct = []
                                            new_rule = Rule(0, 'query_path', protocol_list, [operator],
                                                            port_source_list, [], port_dest_list,
                                                            Action(True))
                                            tmp_struct.append(new_rule)
                                            tmp_struct.append([fw.hostname, operator, new_rule])
                                            data.append(tmp_struct)
        return data

    def ip_operator_compare(self, operator_1, operator_2):
        """
        take two ip_operator in input
        return true if the second one is contain or is equal to the first
        """
        check = False
        # 4294967295 value for 255.255.255.255
        if operator_1.v1.mask != 4294967295:
            tmp_val = 4294967295
            ip_min_check = operator_1.v1.ip & operator_1.v1.mask
            tmp_val = tmp_val ^ operator_1.v1.mask
            ip_max_check = operator_1.v1.ip | tmp_val
            operator_1 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
        if operator_2.v1.mask != 4294967295:
            tmp_val = 4294967295
            ip_min_check = operator_2.v1.ip & operator_2.v1.mask
            tmp_val = tmp_val ^ operator_2.v1.mask
            ip_max_check = operator_2.v1.ip | tmp_val
            operator_2 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
        if operator_1.operator == "RANGE" and operator_2.operator == "RANGE":
            if operator_1.v1.ip <= operator_2.v1.ip <= operator_1.v2.ip:
                if operator_1.v1.ip <= operator_2.v2.ip <= operator_1.v2.ip:
                    check = True
        elif operator_1.operator == "RANGE" and operator_2.operator != "RANGE":
            if operator_1.v1.ip <= operator_2.v1.ip <= operator_1.v2.ip:
                check = True
        elif operator_1.operator != "RANGE" and operator_2.operator == "RANGE":
            if operator_1.v1.ip == operator_2.v1.ip and operator_1.v1.ip == operator_2.v2.ip:
                    check = True
        elif operator_1.operator != "RANGE" and operator_2.operator != "RANGE":
            if operator_1.v1.ip == operator_2.v1.ip:
                check = True
        return check

    def port_operator_compare(self, ope1, ope2):
        data = None
        if ope1.operator == "EQ" and ope2.operator == "EQ":
            if ope1.v1.port == ope2.v1.port:
                data = ope1
        elif ope1.operator == "RANGE" and ope2.operator == "EQ":
            if ope1.v1.port <= ope2.v1.port <= ope1.v2.port:
                data = ope2
        elif ope1.operator == "EQ" and ope2.operator == "RANGE":
            if ope2.v1.port <= ope1.v1.port <= ope2.v2.port:
                data = ope1
        elif ope1.operator == "RANGE" and ope2.operator == "RANGE":
            if ope1.v1.port <= ope2.v1.port <= ope1.v2.port:
                if ope2.v2.port <= ope1.v2.port:
                    data = ope2
                else:
                    data = ope2
                    data.v2.port = ope1.v2.port
            elif ope2.v1.port < ope1.v1.port:
                if ope1.v1.port < ope2.v2.port < ope1.v2.port:
                    data = ope2
                    data.v1.port = ope1.v1.port
                elif ope1.v2.port < ope2.v2.port:
                    data = ope1
        return data

    def protocol_operator_compare(self, ope1, ope2):
        data = None
        if ope1.operator == "EQ" and ope2.operator == "EQ":
            if ope1.v1.protocol == ope2.v1.protocol:
                data = ope1
        elif ope1.operator == "RANGE" and ope2.operator == "EQ":
            if ope1.v1.protocol <= ope2.v1.protocol <= ope1.v2.protocol:
                data = ope2
        elif ope1.operator == "EQ" and ope2.operator == "RANGE":
            if ope2.v1.protocol <= ope1.v1.protocol <= ope2.v2.protocol:
                data = ope1
        elif ope1.operator == "RANGE" and ope2.operator == "RANGE":
            if ope1.v1.protocol <= ope2.v1.protocol <= ope1.v2.protocol:
                if ope2.v2.protocol <= ope1.v2.protocol:
                    data = ope2
                else:
                    data = ope2
                    data.v2.protocol = ope1.v2.protocol
            elif ope2.v1.protocol < ope1.v1.protocol:
                if ope1.v1.protocol < ope2.v2.protocol < ope1.v2.protocol:
                    data = ope2
                    data.v1.protocol = ope1.v1.protocol
                elif ope1.v2.protocol < ope2.v2.protocol:
                    data = ope1
        return data

    def regular_list_compare_operator(self, operators1, operators2):
        """
        Compare two operator list
        return all the element in common in the both list
        """
        return_list = None
        check_list_seria = []
        if not len(operators1) and len(operators2):
            if len(operators2):
                return_list = operators2
        elif len(operators1) and not len(operators2):
            if len(operators1):
                return_list = operators1
        elif not len(operators1) and not len(operators2):
            return_list = []
        elif len(operators1) and len(operators2):
            if isinstance(operators1[0].v1, Port):
                for ope1 in operators1:
                    for ope2 in operators2:
                        compare_ope = self.port_operator_compare(ope1, ope2)
                        if compare_ope is not None:
                            compare_seria = compare_ope.seria_compare()
                            if compare_seria not in check_list_seria:
                                if return_list is None:
                                    return_list = []
                                check_list_seria.append(compare_seria)
                                return_list.append(compare_ope)
            elif isinstance(operators1[0].v1, Protocol):
                for ope1 in operators1:
                    for ope2 in operators2:
                        compare_ope = self.protocol_operator_compare(ope1, ope2)
                        if compare_ope is not None:
                            compare_seria = compare_ope.seria_compare()
                            if compare_seria not in check_list_seria:
                                if return_list is None:
                                    return_list = []
                                check_list_seria.append(compare_seria)
                                return_list.append(compare_ope)
        return return_list

    def _new_get_all_simple_paths(self, source_node, dest_node):
        """Retrieve all simple paths between two node of the graph.
        """
        self.res, self.marks, source_node, dest_node = [], [], source_node, dest_node
        self.marks.append(source_node)
        self.__new_all_simple_paths(source_node, dest_node)

    def __new_all_simple_paths(self, source_node, dest_node):
        """Recursive implementation of DSF search algorithm to find all simple paths
           between two nodes
        """
        if len(self.res) < 100:
            son_list = self.multidigraph.neighbors(source_node)
            for son in son_list:
                if son == dest_node:
                    tmp_list = []
                    for node in self.marks:
                        tmp_list.append(node)
                    tmp_list.append(dest_node)
                    self.res.append(list(tmp_list))
                else:
                    check = True
                    if son is not None:
                        for mark in self.marks:
                            if son.ip == mark.ip and son.mask == mark.mask:
                                check = False
                                break
                        if check:
                            self.marks.append(son)
                            self.__new_all_simple_paths(son, dest_node)
                            self.marks.pop()
    """
    def algo_de_recherche(source, dest, list_of_ip)
        list_ip_reachable = get all ip reachable corresponding to the message
        for ip in list_ip_reachable
            if ip == dest:
                list_of_ip.append(dest)
            if ip is in list_of_ip:
                continue
            else
            list_of_ip = algo_ip_reachable(ip,dest, list_of_ip.append(ip))
    """
    def get_acl_list(self, src=None, dst=None, firewall=None):
        """Get all acl filtered by optional parameters

        Parameters
        ----------
        src : Ip / Firewall (optional). The source of the acl any if src is not defined
        dst : Ip / Firewall (optional). The destination of the acl any if dst is not defined
        firewall : Firewall (optional). Filter acl belonging to this firewall any if firewall is not defined
        """
        acl_list = []
        if src and isinstance(src, Ip) and not self.multidigraph.has_node(src):
            src = Ip.ListContains(self.digraph_subnet_list, src)
        if dst and isinstance(dst, Ip) and not self.multidigraph.has_node(dst):
            dst = Ip.ListContains(self.digraph_subnet_list, dst)

        if src and not self.multidigraph.has_node(src):
            return acl_list

        for elem in self.multidigraph.edges(src, data=True):
            if dst and elem[1] != dst:
                continue
            if firewall and elem[2]['firewall'] != firewall:
                continue
            acl_list.append(elem[2]['acl'])

        return acl_list

    def get_interface_ip(self, acl):
        for edge in self.multidigraph.edges(data=True):
            if edge[2]['acl'] == acl:
                if isinstance(edge[0], Ip):
                    return edge[0]
                if isinstance(edge[1], Ip):
                    return edge[1]
        return None

    def get_firewall_from_acl(self, acl):
        for edge in self.multidigraph.edges(data=True):
            if edge[2]['acl'] == acl:
                return edge[2]['firewall']
        return None

    def set_linewidth(self):
        """Compute line_width based on the number of port, rules, ... (use logarithmic scale)."""
        max_value = 1

        def get_firewall(e0, e1):
            if isinstance(e0, Firewall.Firewall):
                return e0
            if isinstance(e1, Firewall.Firewall):
                return e1
            return None

        def get_ip(e0, e1):
            if isinstance(e0, Ip):
                return e0
            if isinstance(e1, Ip):
                return e1
            return None

        # get max value and set a line width
        for edge in self.graph.edges():
            value = 0
            fw = get_firewall(edge[0], edge[1])
            ip = get_ip(edge[0], edge[1])
            acl_list = self.get_acl_list(ip, None, fw)
            acl_list += self.get_acl_list(None, ip, fw)

            for acl in acl_list:
                for r in acl.rules:
                    if len(r.port_source) == 0:
                        if len(r.port_dest) == 0:
                            value += (64535 * 64535)
                        else:
                            for port_d in r.port_dest:
                                value += (64535 * port_d.get_len())
                    else:
                        for port_s in r.port_source:
                            if len(r.port_dest) == 0:
                                value += (port_s.get_len() * 64535)
                            else:
                                for port_d in r.port_dest:
                                    value += (port_s.get_len() * port_d.get_len())
            max_value = value if value > max_value else max_value
            self.graph[edge[0]][edge[1]]['object'].line_width = value

        # normalize line width
        for edge in self.graph.edges():
            width = self.graph[edge[0]][edge[1]]['object'].line_width
            width = math.log(1.1 + (float(width) / max_value)) * 10
            self.graph[edge[0]][edge[1]]['object'].line_width = width

    def clear(self):
        """Clear the graph"""
        self.firewalls = []
        self.graph = nx.Graph()
        self.subnet_list = []
        self.multidigraph = nx.MultiDiGraph()
        self.digraph_subnet_list = []
        self.node_click = False

    def draw(self, canvas):
        """Draw the networkX graph.
        - Compute line width
        - Draw nodes
        - Draw edges

        Parameters
        ----------
        canvas : a gtk canvas to draw the node and edge objects
        """
        for node in self.graph.nodes():
            self.graph.node[node]['object'].draw(canvas)

        self.set_linewidth()

        for edge in self.graph.edges():
            self.graph[edge[0]][edge[1]]['object'].draw(canvas)