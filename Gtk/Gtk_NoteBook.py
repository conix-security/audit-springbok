#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import re
import gtk
import Gtk_Main
import Gtk_Export
import NetworkGraph.NetworkGraph
import AnomalyDetection.AnomalyError as AnomalyError
import Gtk_HelpMessage
from Gtk_HelpMessage import Gtk_Message
from Gtk_TabInterface import Gtk_TabInterface
from Gtk_ListView import Gtk_ListView
from Gtk_TreeView import Gtk_TreeView
from Gtk_SearchBar import Gtk_SearchBar
from Gtk.Gtk_Matrix_Table import Gtk_Matrix_Table
from Gtk.Gtk_Nat_Rule import Gtk_Nat_Rule
from Gtk_IPSec_Tunnels import Gtk_IPSec_Tunnels
from SpringBase.Ip import Ip
from SpringBase.Operator import Operator

class Gtk_NoteBookSplit:
    """Gtk_NoteBookSplit class.
    This class contains two notebooks used for splitting tab.

    Parameters
    ----------
    notebook : Gtk_NoteBook. The first notebook
    notebook_split : Gtk_NoteBook. The second notebook for splitting

    tab_dict : dict. Dictionary of referenced tabs (used to not reopen these tabs)
    export_tab : dict. Dictionary tab who can be exported

****** Modification ******

        This class has been modified by Maurice TCHAMGOUE on 24-04-2015 for:
        - adding the ability to select some firewalls among multiple ones when
          importing a configuration file wich contains multiple firewalls
          definition (Fortigate or CheckPoint for example)
        - adding the add_matrix_flow_tab method in order to manage the edition
         of the matrix flow file in a new tab
    """
    def __init__(self):
        self.notebook = Gtk_NoteBook(1)
        self.notebook_split = Gtk_NoteBook(1)
        self.notebook.notebook.connect("drag_begin", self.on_drag_begin)
        self.notebook.notebook.connect("drag_end", self.on_drag_end)
        self.notebook_split.notebook.connect("drag_begin", self.on_drag_begin)
        self.notebook_split.notebook.connect("drag_end", self.on_drag_end)
        self.hpaned = gtk.HPaned()
        self.hpaned.pack1(self.notebook.notebook, True, False)
        self.tab_dict = {}
        self.export_tab = {}

    def on_drag_begin(self, widget, context):
        """Event listener begin drag tab"""
        if not self.hpaned.get_child1():
            self.hpaned.pack1(self.notebook.notebook, True, False)
            self.hpaned.set_position(1 * self.hpaned.get_allocation().width / 3)

        if not self.hpaned.get_child2():
            self.hpaned.pack2(self.notebook_split.notebook, True, False)
            self.hpaned.set_position(2 * self.hpaned.get_allocation().width / 3)

        self.hpaned.show_all()

    def on_drag_end(self, widget, context):
        """Event listener end drag tab"""
        self.pane_resize()

    def add_tab(self, obj, name, can_close=False, ref=None, export=None):
        """Add tab to the first notebook.

        Parameters
        ----------
        obj : widget. The widget to add
        name : string. The name of the tab
        can_close : bool. If true, the tab can be closed
        ref : object. Reference to prevent reopening same tab
        export : function. Function callback for exporting
        """
        if not self.hpaned.get_child1():
            self.hpaned.pack1(self.notebook.notebook, True, False)
            self.hpaned.show_all()

        if ref and ref in self.tab_dict:
            if self.notebook.notebook.page_num(self.tab_dict[ref]) != -1:
                self.notebook.notebook.set_current_page(self.notebook.notebook.page_num(self.tab_dict[ref]))
            else:
                self.notebook_split.notebook.set_current_page(self.notebook_split.notebook.page_num(self.tab_dict[ref]))
        else:
            if ref:
                self.tab_dict[ref] = obj
            if export:
                self.export_tab[ref] = export
            hbox = gtk.HBox()
            hbox.pack_start(gtk.Label(name), True, True, 0)
            # Add button closing the notebook page
            if can_close:
                button = gtk.Button("X")
                button.set_size_request(22, 15)
                button.connect("clicked", self.on_tab_close, obj)
                hbox.pack_end(button, False, False, 0)
            hbox.show_all()
            self.notebook.add_tab(obj, hbox)
            self.notebook.notebook.set_tab_detachable(obj, True)

    def pane_resize(self):
        """HPane resize depending on the number of tab in each notebook"""
        if self.notebook.notebook.get_n_pages() == 0 and self.hpaned.get_child1():
            self.hpaned.remove(self.notebook.notebook)

        if self.notebook_split.notebook.get_n_pages() == 0 and self.hpaned.get_child2():
            self.hpaned.remove(self.notebook_split.notebook)

        self.hpaned.show_all()

    def close_all_closable(self):
        """Close all table that can be close"""
        for k, v in self.tab_dict.items():
            if self.notebook.notebook.page_num(v) != -1:
                self.notebook.notebook.remove_page(self.notebook.notebook.page_num(v))
            elif self.notebook_split.notebook.page_num(v) != -1:
                self.notebook_split.notebook.remove_page(self.notebook_split.notebook.page_num(v))
            self.pane_resize()
            self.tab_dict.pop(k)
            if k in self.export_tab:
                self.export_tab.pop(k)

    def on_tab_close(self, widget, obj):
        """Close a page

        Parameters
        ----------
        obj : the object corresponding to the page to close
        """
        if self.notebook.notebook.page_num(obj) != -1:
            self.notebook.notebook.remove_page(self.notebook.notebook.page_num(obj))
        elif self.notebook_split.notebook.page_num(obj) != -1:
            self.notebook_split.notebook.remove_page(self.notebook_split.notebook.page_num(obj))
        self.pane_resize()
        for k, v in self.tab_dict.items():
            if v == obj:
                self.tab_dict.pop(k)
                if k in self.export_tab:
                    self.export_tab.pop(k)

    def add_interface_tab(self, obj):
        """Add an interface page

        Parameters
        ----------
        obj : the interface instance
        """
        if obj not in self.tab_dict:
            # strangely if you remove self to tab_interface, we have problems with garbage collector deleting attributes
            name = "%s (%s)" % (obj.name, NetworkGraph.NetworkGraph.NetworkGraph().get_firewall_from_acl(obj).hostname)
            self.tab_interface = Gtk_TabInterface(name, obj)
            self.tab_interface.add_rules(obj.get_rules())
            self.search_bar = Gtk_SearchBar(obj, self.tab_interface, self.tab_interface.scrolled_window)
            self.add_tab(self.search_bar.vbox, name, can_close=True)
            page_num = self.notebook.notebook.page_num(self.tab_interface.scrolled_window)
            self.tab_dict[obj] = self.search_bar.vbox
            self.notebook.notebook.set_current_page(page_num)
            Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_HelpMessage.Gtk_Message.ON_SHOW_RULES)
        else:
            if self.notebook.notebook.page_num(self.tab_dict[obj]):
                self.notebook.notebook.set_current_page(self.notebook.notebook.page_num(self.tab_dict[obj]))
            elif self.notebook_split.notebook.page_num(self.tab_dict[obj]):
                self.notebook_split.notebook.set_current_page(self.notebook_split.notebook.page_num(self.tab_dict[obj]))

    def add_internal_anomaly_tab(self, internal_detection):
        """Add an internal anomaly page

        Parameters
        ----------
        obj : the internal anomaly instance
        """
        def on_cursor_changed(tree_view):
            tree_row = tree_view.get_selection().get_selected()[1]
            if not tree_row:
                return
            model = tree_view.get_model()
            lateral_pane = Gtk_Main.Gtk_Main().lateral_pane
            lateral_pane.details.clear()
            lateral_pane.details.add_row(AnomalyError.get_error_help(model[tree_row][0], 'internal'))
            lateral_pane.focus_details()

        internal_anomaly = Gtk_ListView("Anomaly detection (internal) : " + internal_detection.firewall.hostname)
        internal_anomaly.tree_view.connect('cursor-changed', on_cursor_changed)
        count = 0

        for elem in internal_detection.result:
            for error in elem:
                fg = 'darkorange' if error.startswith('WARNING') else 'darkgreen'
                bg = '#FFFFFF' if count % 2 == 0 else '#DCDCDC'
                internal_anomaly.add_row(error, foreground=fg, background=bg)
                count += 1
        self.search_bar = Gtk_SearchBar(internal_detection, internal_anomaly, internal_anomaly.scrolled_window)
        self.add_tab(self.search_bar.vbox, "Anomaly detection (%s)" % internal_detection.firewall.hostname,
                     can_close=True, ref=internal_detection, export=Gtk_Export.export_internal_detection)

    def add_distributed_anomaly_tab(self, distributed_detection):
        """Add an distributed anomaly page

        Parameters
        ----------
        obj : the distributed anomaly instance
        """
        def on_cursor_changed(tree_view):
            tree_row = tree_view.get_selection().get_selected()[1]
            if not tree_row:
                return
            model = tree_view.get_model()
            lateral_pane = Gtk_Main.Gtk_Main().lateral_pane
            lateral_pane.details.clear()
            if not model[tree_row].parent:
                lateral_pane.details.add_row("")
            else:
                lateral_pane.details.add_row(AnomalyError.get_error_help(model[tree_row][0], 'distributed'))
            lateral_pane.focus_details()

        distributed_anomaly = Gtk_TreeView("Anomaly detection (distributed)")
        distributed_anomaly.treeview.connect('cursor-changed', on_cursor_changed)
        self._add_distributed_anomaly(distributed_detection.error_path, distributed_anomaly)
        self.search_bar = Gtk_SearchBar(distributed_detection, distributed_anomaly, distributed_anomaly.scrolled_window)
        self.add_tab(self.search_bar.vbox, "Anomaly (Distributed)", can_close=True,
                     ref=distributed_detection, export=Gtk_Export.export_distributed_detection)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_DISTRIBUTED_ANOMALY)

    def _add_distributed_anomaly(self, error_path, treeview, pattern=None):
        """Add error to treeview who match the pattern.

        Parameters
        ----------
        error_path : list. List of error
        treeview : Gtk_Treeview. The treeview to add the row
        pattern : string (optional, default=None). If pattern is not None add only row who match the pattern
        """
        for k, v in error_path:
            if len(v) > 0:
                path = "[ %s ]" % k
                p_iter = treeview.add_row(None, path, '#0E1A24', '#B9B9B9')
                count = 0
                for error in v:
                    if pattern and not re.search(pattern, error, re.I):
                        continue
                    fg = 'darkorange' if error.startswith('WARNING') else 'darkgreen'
                    bg = '#FFFFFF' if count % 2 == 0 else '#DCDCDC'
                    treeview.add_row(p_iter, error, fg, bg)
                    count += 1

    def add_conf_tab(self, file_name, fw_name):
        """Add the configuration file in a new tab.

        Parameters
        ----------
        file_name : string. The file name to show
        fw_name : string. The firewall name of the file name"""
        with open(file_name, "r") as myfile:
            data = myfile.read()

        text_view = gtk.TextView()
        text_view.set_editable(False)
        text_buffer = text_view.get_buffer()
        text_buffer.insert(text_buffer.get_end_iter(), data)

        scrolled_window = gtk.ScrolledWindow()
        scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scrolled_window.add_with_viewport(text_view)
        self.search_bar = Gtk_SearchBar(text_view, text_view, scrolled_window)
        self.add_tab(self.search_bar.vbox, fw_name, can_close=True, ref=file_name)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_HelpMessage.Gtk_Message.ON_SHOW_CONFIGURATION)

    def can_export(self):
        """Return True if the current tab can be exported, False otherwise"""
        for k, v in self.tab_dict.items():
            if v == self.notebook.notebook.get_nth_page(self.notebook.notebook.current_page()):
                if k in self.export_tab:
                    return True
        return False

    def export(self, filename):
        """Export the current tab to the given file name

        Parameters
        ----------
        filename : string. The destination file"""
        for k, v in self.tab_dict.items():
            if v == self.notebook.notebook.get_nth_page(self.notebook.notebook.current_page()):
                if k in self.export_tab:
                    Gtk_Export.Gtk_Export(filename, self.export_tab[k], k).save()


    ##### !!!!! Modification !!!!! #####

    def add_matrix_flow_tab(self, file_name):
        """Add the matrix flow file in a new tab.

        Parameters
        ----------
        file_name : string. The file name to show"""
        with open(file_name, "r") as myfile:
            data = myfile.read()

        text_view = gtk.TextView()
        text_view.set_editable(True)
        text_buffer = text_view.get_buffer()
        text_buffer.insert(text_buffer.get_end_iter(), data)

        scrolled_window = gtk.ScrolledWindow()
        scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scrolled_window.add_with_viewport(text_view)
        self.search_bar = Gtk_SearchBar(text_view, text_view, scrolled_window)
        launch_button = gtk.Button('Launch matrix verification')
        self.search_bar.vbox.add(launch_button)
        self.add_tab(self.search_bar.vbox, "Matrix flow", can_close=True, ref=file_name)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message\
            (Gtk_HelpMessage.Gtk_Message.ON_IMPORT_MATRIX_FLOW)

    def add_matrix_flow_tab2(self, flowlist, firewalls, filename):
        flowlist = self.reduce_rule(flowlist)
        table = Gtk_Matrix_Table(flowlist, firewalls)
        vbox = table.vbox
        self.add_tab(vbox, 'Matrix flow', can_close=True, ref=filename)

    def add_nat_rule_tab(self, firewall, nat_rule_list):
        table = Gtk_Nat_Rule(nat_rule_list, firewall)
        vbox = table.vbox
        self.add_tab(vbox, 'Nat rules -- ' + firewall.hostname, can_close=True, ref=firewall.hostname + 'nat')

    def add_ipsec_tunnels(self, firewall, ipsec_tunnels):
        table = Gtk_IPSec_Tunnels(ipsec_tunnels, firewall)
        vbox = table.vbox
        self.add_tab(vbox, 'IPSec Tunnels -- ' + firewall.hostname, can_close=True, ref=firewall.hostname + 'ipsec')

    def reduce_rule(self, rulelist):
        """
        Merge all the rules which can be merge in the rulelist
        """
        rulelist_to_reduce = self.detect_reduce_rule(rulelist)
        while rulelist_to_reduce:
            items_to_delete = {}
            for rule_to_reduce in rulelist_to_reduce:
                rule = self.merge_two_rules(rulelist[rule_to_reduce[0]], rulelist[rule_to_reduce[1]])
                items_to_delete[rule_to_reduce[0]] = ""
                items_to_delete[rule_to_reduce[1]] = ""
                rulelist.append(rule)
            rulelist = [i for j, i in enumerate(rulelist) if j not in items_to_delete]
            rulelist_to_reduce = self.detect_reduce_rule(rulelist)
        return rulelist

    def detect_reduce_rule(self, rulelist):
        """
        Detect in a list of rules if there is any couple of rule
        which can be merged
        """
        rulelist_to_reduce = []
        rulelist_use = {}
        for idx, rule in enumerate(rulelist):
            if idx in rulelist_use:
                continue
            for idx_tmp, tmp_rule in enumerate(rulelist):
                if idx_tmp in rulelist_use:
                    continue
                if rule != tmp_rule and self.is_action_equals(rule.action, tmp_rule.action):
                    count = 0

                    if self.is_operator_list_equals(rule.ip_source, tmp_rule.ip_source):
                        count += 1
                    if self.is_operator_list_equals(rule.port_source, tmp_rule.port_source):
                        count += 1
                    if self.is_operator_list_equals(rule.ip_dest, tmp_rule.ip_dest):
                        count += 1
                    if self.is_operator_list_equals(rule.port_dest, tmp_rule.port_dest):
                        count += 1
                    if self.is_operator_list_equals(rule.protocol, tmp_rule.protocol):
                        count += 1
                    if count > 3:
                        rulelist_use[idx] = ""
                        rulelist_use[idx_tmp] = ""
                        rulelist_to_reduce.append([idx, idx_tmp])
                        break
        return rulelist_to_reduce

    def merge_two_rules(self, rule1, rule2):
        """
        merge two rules in only one
        Each rule should have at least 3 same items in the following list and the same action:
        ip_source, port_source, ip_dest, port_dest
        """
        if self.is_action_equals(rule1.action, rule2.action):

            ip_source = self.is_operator_list_equals(rule1.ip_source, rule2.ip_source)
            port_source = self.is_operator_list_equals(rule1.port_source, rule2.port_source)
            ip_dest = self.is_operator_list_equals(rule1.ip_dest, rule2.ip_dest)
            port_dest = self.is_operator_list_equals(rule1.port_dest, rule2.port_dest)
            action = self.is_action_equals(rule1.action, rule2.action)
            protocol = self.is_operator_list_equals(rule1.protocol, rule2.protocol)
            if action:
                if not ip_source:
                    rule1.ip_source = self.merge_two_operator_list(rule1.ip_source, rule2.ip_source)
                elif not port_source:
                    rule1.port_source = self.merge_two_operator_list(rule1.port_source, rule2.port_source)
                elif not ip_dest:
                    rule1.ip_dest = self.merge_two_operator_list(rule1.ip_dest, rule2.ip_dest)
                elif not port_dest:
                    rule1.port_dest = self.merge_two_operator_list(rule1.port_dest, rule2.port_dest)
                elif not protocol:
                    rule1.protocol = self.merge_two_operator_list(rule1.protocol, rule2.protocol)
        return rule1

    def merge_two_operator_list(self, operators1, operators2):
        """
        Merge two operators list in a unique one
        """
        final_list = []
        if (not len(operators1)) or (not len(operators2)):
            return final_list
        result_list = self.compare_operator_list(operators1, operators2)
        for item in result_list:
            if item[1] == 1:
                final_list.append(operators1[item[0]])
            if item[1] == 2:
                final_list.append(operators2[item[0]])
        if isinstance(final_list[0].v1, Ip):
            final_list = self.check_ip_merge(final_list)
        return final_list

    def check_ip_merge(self, final_list):
        """
        Change each mask of ip into Range of IP
        Then detect every possible link between range/ip
        and merge the possible ip/range
        """
        to_delete = {}
        for idx, ip_check1 in enumerate(final_list):
            # Value of ip 255.255.255.255 in int is 4294967295
            if ip_check1.v1.mask != 4294967295:
                tmp_val = 4294967295
                ip_min_check = ip_check1.v1.ip & ip_check1.v1.mask
                tmp_val = tmp_val ^ ip_check1.v1.mask
                ip_max_check = ip_check1.v1.ip | tmp_val
                ip_check1 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
                final_list[idx] = ip_check1
            for idx2, ip_check2 in enumerate(final_list):
                if idx2 in to_delete or idx == idx2:
                    continue
                if ip_check2.v1.mask != 4294967295:
                    tmp_val = 4294967295
                    ip_min_check = ip_check2.v1.ip & ip_check2.v1.mask
                    tmp_val = tmp_val ^ ip_check2.v1.mask
                    ip_max_check = ip_check2.v1.ip | tmp_val
                    ip_check2 = Operator("RANGE", Ip(ip_min_check), Ip(ip_max_check))
                    final_list[idx2] = ip_check2
                if ip_check1.operator == "EQ" and ip_check2.operator == "EQ":
                    val_ip1 = ip_check1.v1.ip & ip_check2.v1.mask
                    val_ip2 = ip_check2.v1.ip & ip_check2.v1.mask
                    if val_ip1 == val_ip2:
                        to_delete[idx] = ""
                else:
                    ip_min = None
                    ip_max = None
                    ip_to_compare_min = None
                    ip_to_compare_max = None
                    if ip_check1.operator == "RANGE" and ip_check2.operator == "RANGE":
                        ip_min = ip_check1.v1
                        ip_max = ip_check1.v2
                        ip_to_compare_min = ip_check2.v1
                        ip_to_compare_max = ip_check2.v2
                    elif ip_check1.operator == "RANGE":
                        ip_min = ip_check1.v1
                        ip_max = ip_check1.v2
                        ip_to_compare_min = ip_check2.v1
                    elif ip_check2.operator == "RANGE":
                        ip_min = ip_check2.v1
                        ip_max = ip_check2.v2
                        ip_to_compare_min = ip_check1.v1
                    result = self.merge_ip_range(ip_min, ip_max, ip_to_compare_min, ip_to_compare_max)
                    if result:
                        if idx > idx2:
                            final_list[idx] = result
                            to_delete[idx2] = ""
                        else:
                            final_list[idx2] = result
                            to_delete[idx] = ""


        final_list = [i for j, i in enumerate(final_list) if j not in to_delete]
        return final_list

    def merge_ip_range(self, ip_min, ip_max, ip_to_compare_min, ip_to_compare_max):
        """
        The function merge 2 range or 1 range and one ip
        If the merge is possible return the new operator otherwise return nothing
        ip_min/ip_max are the ip for the first range
        ip_to_compare_min/ip_to_compare_max is the second range
        to compare to an ip just send a non value for ip_to_compare_max
        """
        ip1 = None
        ip2 = None
        operator = None
        if (not ip_to_compare_max) and (ip_min <= ip_to_compare_min <= ip_max):
            ip1 = Ip(ip_min.ip)
            ip2 = Ip(ip_max.ip)
        elif ip_to_compare_max:
            if ip_min.ip <= ip_to_compare_min.ip <= ip_max.ip:
                ip1 = Ip(ip_min.ip)
                ip2 = Ip(ip_max.ip) if ip_max.ip > ip_to_compare_max.ip else Ip(ip_to_compare_max.ip)
            elif ip_min.ip <= ip_to_compare_max.ip <= ip_max.ip:
                ip1 = Ip(ip_to_compare_min.ip)
                ip2 = Ip(ip_max.ip)
            elif ip_to_compare_min.ip < ip_min.ip and ip_to_compare_max.ip > ip_max.ip:
                ip1 = Ip(ip_to_compare_min.ip)
                ip2 = Ip(ip_to_compare_max.ip)
        if ip1 and ip2:
            operator = Operator("RANGE", ip1, ip2)
        return operator

    def compare_operator_list(self, operators1, operators2):
        """
        Compare two operator list and return a list
        The return list contains every component to select in order
        to create a unique operators
        """
        operators1_seria = [i.seria_compare() for i in operators1]
        operators2_seria = [i.seria_compare() for i in operators2]
        comparator_list = set(operators1_seria + operators2_seria)
        result_list = []
        for item in comparator_list:
            found = False
            for i, j in enumerate(operators1_seria):
                if j == item:
                    result_list.append([i, 1])
                    found = True
                    break
            if found:
                continue
            for i, j in enumerate(operators2_seria):
                if j == item:
                    result_list.append([i, 2])
                    break
        return result_list

    def is_operator_list_equals(self, operators1, operators2):
        """
        Return true if operators list are equals return false otherwise
        """
        check = True
        operators1_seria = [i.seria_compare() for i in operators1]
        operators2_seria = [i.seria_compare() for i in operators2]
        comparator_list = set(operators1_seria + operators2_seria)
        len_comparator = len(comparator_list)
        if (len_comparator != len(operators1_seria)) or (len_comparator != len(operators2_seria)):
            check = False
        return check

    def is_action_equals(self, action1, action2):
        return (action1.chain == action2.chain) and (action1.goto == action2.goto)

class Gtk_NoteBook:
    """Gtk_NoteBook class.
    A notebook interface for adding/removing page with optional close button.

    Parameters
    ----------
    notebook : gtk notebook
    tab_dict : dict. Dictionnary of existing interface page (used to prevent duplicate page)
    """
    def __init__(self, group_id=-1):
        self.notebook = gtk.Notebook()
        self.notebook.set_tab_pos(gtk.POS_TOP)
        self.notebook.set_scrollable(True)
        self.notebook.set_group_id(group_id)

    def do_connect(self):
        """Activate connection for 'switch-page' event"""
        self.notebook.connect("switch-page", self.on_change_page)

    def on_change_page(self, notebook, page, page_num):
        """Event listener switch-page. Change message in the help box"""
        Gtk_Main.Gtk_Main().lateral_pane.details.clear()
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_CHANGE_TAB)

    def add_tab(self, obj, label, expand=False):
        """Add a page to the notebook

        Parameters
        ----------
        obj : gtk object. a gtk object to show in the new page
        name : string or label. the name of the page
        expand : bool (optional, default=False). Expand the page if true
        can_close: bool (optional, default=False). If true add a small button enabling to close the page
        """
        gtk_label = label
        if isinstance(label, str):
            gtk_label = gtk.Label(label)
        self.notebook.append_page(obj, gtk_label)
        self.notebook.child_set(obj, "tab-expand", expand)
        self.notebook.show_all()
        self.notebook.set_current_page(self.notebook.page_num(obj))
