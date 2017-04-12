#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
from reportlab.graphics.widgetbase import Face

pygtk.require("2.0")
import gtk
import Gtk_Main
from Gtk_DialogBox import Gtk_DialogBox
from Gtk_TreeView import Gtk_TreeView
import Gtk_Export
import itertools
from NetworkGraph import NetworkGraph
from SpringBase import *
from ROBDD.synthesis import synthesize
from ROBDD.operators import Bdd
#from SpringBase.Firewall import Firewall
import time
from graphviz import Digraph

class Gtk_QueryPath:
    """Gtk_QueryPath class.
    A class to perform query path. This class enable to search all simple path between two points
    filtered on protocol, ip source, port source, ip destination and port destination

    Parameters
    ----------
    source_entry : Ip. Predefined ip source
    dest_entry : Ip. Predefined ip destination
    """
    def __init__(self, source_entry=None, dest_entry=None):
        self.popup = gtk.Window()
        self.popup.set_title("Query Path")
        self.popup.set_modal(True)
        self.popup.set_transient_for(Gtk_Main.Gtk_Main().window)

        self.popup.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)

        vbox = gtk.VBox()
        vbox.pack_start(gtk.Label("Query Path :"))

        self.protocol_label = gtk.Label("Protocol :")
        self.protocol_entry = gtk.Entry()
        vbox.pack_start(self.protocol_label)
        vbox.pack_start(self.protocol_entry)

        self.ip_source_label = gtk.Label("IP source :")
        self.ip_source_entry = gtk.Entry()
        vbox.pack_start(self.ip_source_label)
        vbox.pack_start(self.ip_source_entry)

        self.mask_source_label = gtk.Label("Mask source :")
        self.mask_source_entry = gtk.Entry()
        vbox.pack_start(self.mask_source_label)
        vbox.pack_start(self.mask_source_entry)

        if source_entry is not None:
            self.ip_source_entry.set_text(Ip.Ip.toString(source_entry.ip))
            self.mask_source_entry.set_text(Ip.Ip.toString(source_entry.mask))

        self.port_source_label = gtk.Label("Port source :")
        self.port_source_entry = gtk.Entry()
        vbox.pack_start(self.port_source_label)
        vbox.pack_start(self.port_source_entry)

        self.ip_dest_label = gtk.Label("IP destination :")
        self.ip_dest_entry = gtk.Entry()
        vbox.pack_start(self.ip_dest_label)
        vbox.pack_start(self.ip_dest_entry)

        self.mask_dest_label = gtk.Label("Mask destination :")
        self.mask_dest_entry = gtk.Entry()
        vbox.pack_start(self.mask_dest_label)
        vbox.pack_start(self.mask_dest_entry)

        if dest_entry is not None:
            self.ip_dest_entry.set_text(Ip.Ip.toString(dest_entry.ip))
            self.mask_dest_entry.set_text(Ip.Ip.toString(dest_entry.mask))

        self.port_dest_label = gtk.Label("Port destination :")
        self.port_dest_entry = gtk.Entry()
        vbox.pack_start(self.port_dest_label)
        vbox.pack_start(self.port_dest_entry)

        self.button_cancel = gtk.Button("Cancel")
        self.button_cancel.connect("clicked", lambda x: self.popup.destroy())
        self.button_start = gtk.Button("Run Query")
        self.button_start.connect("clicked", self.on_click)
        self.hbox = gtk.HBox()
        self.hbox.pack_start(self.button_cancel)
        self.hbox.pack_start(self.button_start)
        vbox.pack_start(self.hbox)

        self.popup.add(vbox)
        self.popup.show_all()

    def on_click(self, widget):
        """
        Event listener : launch when "Run Query" is clicked.
        Launch the query path search algorithm.
        """
        protocol_op = []
        ip_source_op = []
        port_source_op = []
        ip_dest_op = []
        port_dest_op = []

        if self.protocol_entry.get_text() != '':
            protocol_op = [Operator.Operator('EQ', Protocol.Protocol(self.protocol_entry.get_text()))]
        if self.ip_source_entry.get_text() != '':
            mask_src = self.mask_source_entry.get_text() if self.mask_source_entry.get_text() else '255.255.255.255'
            ip_source_op = [Operator.Operator('EQ', Ip.Ip(self.ip_source_entry.get_text(), mask_src))]
        if self.port_source_entry.get_text() != '':
            port_source_op = [Operator.Operator('EQ', Port.Port(self.port_source_entry.get_text()))]
        if self.ip_dest_entry.get_text() != '':
            mask_dst = self.mask_dest_entry.get_text() if self.mask_dest_entry.get_text() else '255.255.255.255'
            ip_dest_op = [Operator.Operator('EQ', Ip.Ip(self.ip_dest_entry.get_text(), mask_dst))]
        if self.port_dest_entry.get_text() != '':
            port_dest_op = [Operator.Operator('EQ', Port.Port(self.port_dest_entry.get_text()))]

        test_rule = Rule.Rule(0, 'query_path', protocol_op, ip_source_op, port_source_op, ip_dest_op, port_dest_op,
                              Action.Action(True))

        self.popup.destroy()

        res = []


        #try:
        res, routedPaths = run_query(test_rule)
        if not res:
            Gtk_DialogBox("No path found !")
        # except:
            # message popup if no result


        g = NetworkGraph.NetworkGraph()

        # clear old path
        Gtk_Main.Gtk_Main().lateral_pane.path.clear()
        Gtk_Main.Gtk_Main().lateral_pane.path_route.clear()
        for edge in g.graph.edges(data=True):
            edge[2]['object'].clear_path()

        # construct and add path string
        """
        for path_data in res:
            path = path_data[0]
            i = 0
            while i < len(path) - 1:
                # mark path
                g.graph[path[i]][path[i + 1]]['object'].mark_path()
                i += 1
            Gtk_Main.Gtk_Main().lateral_pane.path.add_row(path_to_string(path_data[0], '\n'))
        """
        routedPaths = []
        # add routed path result
        for path_data in routedPaths:
            path = path_data[0]
            i = 0
            while i < len(path) - 1:
                # mark path
                g.graph[path[i]][path[i + 1]]['object'].mark_path()
                i += 1
            Gtk_Main.Gtk_Main().lateral_pane.path_route.add_row(path_to_string(path_data[0], '\n'))

        # Gtk_Main.Gtk_Main().lateral_pane.path_data = res
        Gtk_Main.Gtk_Main().lateral_pane.focus_path()
        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")


def path_to_string(path, separator):
    """Convert the given path to a string format

    Parameters
    ----------
    path : list. List of path to convert
    separator : string. Used to separate each element in the path

    Return
    ------
    Return the string formatted path"""
    i = 0
    path_string = "Path :" + separator + "["
    while i < len(path):
        if isinstance(path[i], Firewall.Firewall):
            path_string += path[i].hostname
        elif isinstance(path[i], Ip.Ip):
            path_string += path[i].to_string()

        if i < len(path) - 1:
            path_string += "," + separator
        i += 1
    path_string += "]"

    return path_string


def treeview_output(query_path):
    """Add a tab in the notebook showing the result of the query path.

    Parameters
    ----------
    query_path : list. List of query path result to show
    """
    result = query_path.result
    treeview = Gtk_TreeView("Query Path Import")
    for i in result:
        rule = i[0]
        path_data = i[1]
        fg_color = 'darkred' if not path_data else '#DDDD00' if isinstance(path_data[0], str) else 'darkgreen'
        p0 = treeview.add_row(None, rule.to_string(' '), fg_color, '#969696')
        if isinstance(path_data, str):
            treeview.add_row(p0, path_data, 'black', '#B9B9B9')
            continue
        for data in path_data:
            p1 = treeview.add_row(p0, path_to_string(data[0], ' '), 'black', '#B9B9B9')
            count = 0
            for r in data[1]:
                treeview.add_row(p1, r[1].to_string(' '), 'black', '#DCDCDC' if count % 2 else '#FFFFFF')
                count += 1
    Gtk_Main.Gtk_Main().notebook.add_tab(treeview.scrolled_window, "Query path import", can_close=True,
                                         ref=query_path, export=Gtk_Export.export_query_path)

def create_graph(simple_path):
    dot = Digraph(comment='Query Result')
    current_node = 0
    dictionnary = {}
    link_dictionnary = {}
    previous_node = None
    for idx1, path in enumerate(simple_path):
        for idx2, component in enumerate(path):

            tmp_node = current_node
            current_data_string = ""
            if len(component) == 2:
                current_data_string = component[0].hostname
            elif len(component) == 5:
                if len(component[4]):
                    current_data_string += "Protocol: " + component[4][0].to_string()
                for idx, data in enumerate(component[4]):
                    if idx:
                        current_data_string += ", " + data.to_string()
                current_data_string += "\nFrom: " + component[0].to_string()
                if len(component[2]):
                    current_data_string += '\nport: ' + component[2][0].to_string()
                for idx,data in enumerate(component[2]):
                    if idx:
                        current_data_string += ", " + data.to_string()
                current_data_string += "\n\nTo: " + component[1].to_string()
                if len(component[3]):
                    current_data_string += '\nport:' + component[3][0].to_string()
                for idx, data in enumerate(component[3]):
                    if idx:
                        current_data_string += ", " + data.to_string()
            if current_data_string in dictionnary:
                tmp_node = dictionnary[current_data_string]
            else:
                dictionnary[current_data_string] = tmp_node
            dot.node(str(tmp_node), current_data_string)
            if idx2 != 0:
                link = str(previous_node) + "-" + str(tmp_node)
                if link not in link_dictionnary:
                    link_dictionnary[link] = ""
                    dot.edge(str(previous_node), str(tmp_node))

            previous_node = tmp_node
            current_node += 1

    dot.render('output/query-result.gv', view=True)


def run_query(rule, ip_source=None, ip_dest=None):
    """Get all simple path, run query and return a formatted result list.

    Parameters
    ----------
    rule : Rule. The rule to test
    ip_source : Ip (optional, default=None). If not None, specify the interface source
    ip_dest : Ip (optional, default=None). If not None, specifu the interface destination

    Return
    ------
    Return a formatted list containing data about matching path
    """
    res = []

    g = NetworkGraph.NetworkGraph()


    # get all simple path
    start = time.time()
    simple_path = g.get_all_simple_path_new(rule, [])
    if len(simple_path):
        create_graph(simple_path)
        return (["success"],[])
    else:
        return ([],[])

    simple_path = g.get_all_simple_path(ip_source, ip_dest)
    end = time.time()
    print 'temps mis = ', str(end - start)
    print 'simple len', len(simple_path)


    for node in g.graph.nodes(data=True):
        if node[1]['object'].marker_type == 'from':
            ip_source = node[0]
        if node[1]['object'].marker_type == 'to':
            ip_dest = node[0]

    """
    simple_path = []
    [simple_path.append(i) for i in g.get_all_simple_path(ip_source, ip_dest)]
    # delete double
    simple_path.sort()
    simple_path = list(simple_path for simple_path, _ in itertools.groupby(simple_path))
    """


    ress = []
    count = 0
    length = len(simple_path)
    for i in range(len(simple_path)):
        pass # print simple_path[i]
    for path in simple_path:
        i = 0
        trouve = False
        while i < len(path):
            if i < len(path) - 1:
                # if path[i] and path[i + 1] are ip, find the corresponding firewall to add in the path, so we can
                # mark the path passing through the firewall
                if not isinstance(path[i], Firewall.Firewall) and not isinstance(path[i + 1], Firewall.Firewall):
                    # get the firewall
                    trouve = True
            i += 1
        if trouve == False:
            ress.append(path)
    simple_path = list(ress)
    # parse all path
    for path in simple_path:
        count += 1
        Gtk_Main.Gtk_Main().statusbar.change_message("QueryPath : test path %d of %d" % (count, length))
        Gtk_Main.Gtk_Main().update_interface()
        # list of rule list
        rule_list = [[]]
        i = 0
        while i < len(path) - 1:
            # list of acl between path[i] and path[i + 1] who match the query
            acl_list = []
            for acl in g.get_acl_list(path[i], path[i + 1]):
                sub_rule = get_subset_rule(rule, acl.get_rules())
                if sub_rule and sub_rule.action.chain:
                    acl_list.append((acl, sub_rule))
            # acl_list empty : this mean we don't find an accepting rule between path[i] and path[i + 1]
            # so we give up
            if not acl_list:
                break

            # duplicate rule_list depending on the number of acl found in acl_list
            # this mean that if we found to acl who match the query between path[i] and path[i + 1],
            # we duplicate the rule_list to have all acl and rules possible
            rule_list += [list(l) for l in rule_list for _ in xrange(len(acl_list) - 1)]
            [rule_list[j].append(acl_list[j * len(acl_list) / len(rule_list)]) for j in xrange(len(rule_list))]
            i += 1

        if i == len(path) - 1:
            # res += [(list(path), rule_list[0])]
            # res += [(list(path), [l for l in rule_list])]

            for l in rule_list:
                # add the path list for each list in rule_list
                res += [(list(path), l)]

    # format result #
    for path_data in res:
        path = path_data[0]
        i = 0
        acl_index = 0
        while i < len(path):
            if i < len(path) - 1:
                # if path[i] and path[i + 1] are ip, find the corresponding firewall to add in the path, so we can
                # mark the path passing through the firewall
                if not isinstance(path[i], Firewall.Firewall) and not isinstance(path[i + 1], Firewall.Firewall):
                    # get the firewall
                    fw = [fw for fw in g.firewalls for acl in g.get_acl_list(firewall=fw)
                          if acl == path_data[1][acl_index][0]][0]
                    path.insert(i + 1, fw)
                    acl_index -= 1
            i += 1
            acl_index += 1
    routed_paths = get_routed_paths(list(res), ip_dest)
    # print res[0][0]

    # delete double from res

    # remove_double(res)
    # remove_bad_path(res)
    # print 'res', res

    # delete bad results : path containing the same firewall twice or more

    return (res, routed_paths)


def get_routed_paths(res, ip_dest):
    finalRes = list(res)
    for path in [p[0] for p in res]:
        good_path = True
        for elt in path:
            if isinstance(elt, Firewall.Firewall):
                route_list = list(elt.route_list)
                route = listContains(route_list, ip_dest)
                if route:
                    if route.iface.network.to_string() not in [iface.network.to_string() for iface in elt.interfaces]:
                        good_path = False
                else:
                    good_path = False
        if good_path == False:
            for a in res:
                if a[0] == path:
                    finalRes.remove(a)
    print 'final', len(finalRes), finalRes
    return list(finalRes)



def listContains(route_list, ip_dest):
    for route in route_list:
        if ip_dest.ip & route.net_ip_dst.ip & route.net_ip_dst.mask ==\
            ip_dest.ip & route.net_ip_dst.mask & ip_dest.mask:
            return route
        return None

def remove_double(res):
    trouve = False
    for elt in res:
        path = elt[0]
        if occ_list(path, [a[0] for a in res]) > 1:
            res.remove(elt)
            trouve = True
    if trouve == True:
        remove_double(res)
    else:
        #print 'ares', len(res), res
        return res


def remove_bad_path(res):
    trouve = False
    trouve2 = False
    for elt in res:
        path = elt[0]
        trouve = False
        for i in path:
            if occ(i, path) > 1:
                trouve = True
                trouve2 = True
        if trouve == True:
            if elt in res:
                res.remove(elt)
            #print 'after', len(res)
    if trouve2 == True:
        remove_bad_path(res)
    else:
        return res


def get_subset_rule(test_rule, rules):
    """Construct the rule and try to find if it is a subset of a rule in the given list"""
    for rule in rules:
        if rule.action.is_chained() or rule.action.is_return():
            continue
        if is_subset(rule, test_rule):
            return rule
    return None


def is_subset(rule, test_rule):
    """return True if rule is a subset of test_rule, false otherwise (use ROBDD)"""
    return len(synthesize(test_rule.toBDD(), Bdd.IMPL, rule.toBDD()).items) <= 2


def occ_list(a, p):
    cptr = 0
    for i in range(len(p)):
        if cmp_list(a, p[i]):
            cptr += 1
    return cptr

def occ(a, p):
    cptr = 0
    for i in range(len(p)):
        if a == p[i]:
            cptr += 1
    return cptr

def is_good(p):
    for elt in p:
        p_test = list(p)
        p_test = list(p_test.remove(elt))
        if occ(elt, p_test) > 1:
            return 0

def cmp_list(a, b):
    if len(a) != len(b):
        return False
    else:
        for i, j in zip(a, b):
            if i.to_string() != j.to_string():
                return False
    return True

