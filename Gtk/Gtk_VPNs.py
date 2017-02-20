__author__ = 'maurice'

#! /usr/bin/python
#coding:utf8

import pygtk
pygtk.require('2.0')
import gtk


from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Action import Action
from SpringBase.ACL import ACL
from SpringBase.Firewall import Firewall
from ROBDD.synthesis import synthesize
from ROBDD.synthesis import Bdd
from Gtk_HelpMessage import Gtk_Message
import Gtk_Main
from socket import inet_ntoa
from struct import pack

class Gtk_Matrix_Table:


    # To add a new row in the matrix table
    def add_row(self, elements=None):
        self.liststore.append(elements)

    def add_empty_row(self, widget):
        if len(self.liststore) != 0:
            self.liststore.append([str(int(self.liststore[-1][0]) + 1),
                                       None, None, None, None, None, None, False, 'white'])
        elif len(self.liststore) == 0:
            self.liststore.append(['0',
                                       None, None, None, None, None, None, False, 'white'])
        self.id_calculation()

    #to remove an element in the matrix table (by its reference)
    def remove_row(self, liststore, ref):
        liststore.remove(ref)

    # to remove all selected flaws in the matrix table
    def remove_selected_rows(self, widget):
        for row in self.liststore:
            if row[7] == True:
                self.liststore.remove(row.iter)
        self.id_calculation()

    ## to fix the id of each row of the table after insertion,
    #  deletion...of a row
    def id_calculation(self):
        j = 0
        for i in range(len(self.liststore)):
            self.liststore[j][0] = str(j)
            j += 1

    # to clear the whole matrix tab
    def clear_liststore(self, liststore):
        liststore.clear()

    # to retrieve data in a cell
    def get_one_value(self, liststore, iter, column):
        return liststore.get_value(iter, column)

    # to update datas when modified by the user
    def on_modify_value(self, cellrenderer, path, new_value, liststore, column):
        print "updating '%s' to '%s'" % (liststore[path][column], new_value)
        liststore[path][column] = new_value
        return

    # to manage toggle button
    def on_selected (self, cellrenderer, path, liststore, column):
        liststore[path][7] = not liststore[path][7]
        return

    # to change the color of a row
    def modify_row_color(self, liststore, path, color):
        liststore[path][8] = color

    # to change the color of a row by
    def modify_row_color2(self, row, color):
        row[8] = color

    ### this function is intend to retrieve the flows in the matrix
    #   table as Rules, and return them into a list (of Rule  instance)
    def get_all_flows(self):
        for flow in self.liststore:
            current_rule = Rule(None, None, [], [], [], [], [], Action(False))
            try:
                if isinstance(flow[0], str) and len(flow[0]) != 0:
                    current_rule.identifier = int(flow[0])
                if isinstance(flow[1], str) and len(flow[1]) != 0:
                    protocols = flow[1].split(',')
                    for protocol in protocols:
                        current_rule.protocol.append(Operator('EQ', Protocol(protocol)))
                if isinstance(flow[2], str) and len(flow[2]) != 0:
                    ips = flow[2].split(',')
                    for ip in ips:
                        if '/' in ip:
                            mask = ip[ip.index('/')+1:]
                            ip = ip[:ip.index('/')]
                            current_rule.ip_source.append(Operator('EQ', Ip(ip, self.fromDec2Dotted(int(mask)))))
                        else:
                            current_rule.ip_source.append(Operator('EQ', Ip(ip, '255.255.255.255')))
                if isinstance(flow[3], str) and len(flow[3]) != 0:
                    ports = flow[3].split(',')
                    for port in ports:
                        current_rule.port_source.append(Operator('EQ', Port(int(port))))
                if isinstance(flow[4], str) and len(flow[4]) != 0:
                    ips = flow[4].split(',')
                    for ip in ips:
                        if '/' in ip:
                            mask = ip[ip.index('/')+1:]
                            ip = ip[:ip.index('/')]
                            current_rule.ip_dest.append(Operator('EQ', Ip(ip, self.fromDec2Dotted(int(mask)))))
                        else:
                            current_rule.ip_dest.append(Operator('EQ', Ip(ip, '255.255.255.255')))
                if isinstance(flow[5], str) and len(flow[5]) != 0 :
                    ports = flow[5].split(',')
                    for port in ports:
                        current_rule.port_dest.append(Operator('EQ', Port(int(port))))
                if flow[6] == 'deny':
                    current_rule.action = Action(False)
                elif flow[6] == 'accept':
                    current_rule.action = Action(True)
            except KeyError:
                print 'error'#
            self.flows.append(current_rule)

    ####  To launch the matrix verification : it will first call the 'get_all_flows'
    #     method to grab all the flow to test, and apply the verification of
    #     all these flows on the selected firewall
    def launch_verification(self, widget):
        self.flows = []
        self.result.clear()
        self.get_all_flows()
        print [flow.to_string() for flow in self.flows]
        for flow in self.flows:
            for acl in self.firewall.acl:
                for rule in acl.rules:
                    print (self.is_subset(rule, flow) == True), (flow.action.to_string() != rule.action.to_string())
                    if  ((self.is_subset(rule, flow) == True) and (flow.action.to_string() != rule.action.to_string())):
                        if self.result.has_key(flow.identifier):
                            self.result[flow.identifier].append((rule, self.firewall))
                        else:
                            self.result[flow.identifier] = []
                            self.result[flow.identifier].append((rule, self.firewall))
        self.show_results_as_colors()

    ## this medthod return True if rule is a subset of test_rule,
    #  false otherwise (using ROBDD)
    def is_subset(self, rule, test_rule):
        return len(synthesize(test_rule.toBDD(), Bdd.IMPL, rule.toBDD()).items) <= 2

    ## this function just output matrix verification result by coloring
    #  in green or red flows in the matrix flow table according to their fitness
    #  for the firewall
    def show_results_as_colors(self):
        reds = [row for row in self.liststore if int(row[0]) in self.result.keys()]
        greens = [row for row in self.liststore if int(row[0]) not in self.result.keys()]
        for row in reds:
            self.modify_row_color2(row, 'red')
        for row in greens:
            self.modify_row_color2(row, 'green')

    ## return a string representation of the attribute(ip, port, protocol...)
    def un_list(self, aList):
        result = ''
        for element in aList:
            if isinstance(element.v1, Protocol):
                result += element.v1.get_service_name(element.v1.get_value()) + ', '
            elif isinstance(element.v1, Port):
                result += str(element.v1.get_value()) + ', '
            elif isinstance(element.v1, Ip):
                result += element.v1.to_string() + ', '
        return result[:-2]

    ## to fill the matrix flow table with imported flows
    def add_flows_to_table(self, flowlist):
        for flow in flowlist:
            self.add_row(['0', self.un_list(flow.protocol), self.un_list(flow.ip_source),
                          self.un_list(flow.port_source), self.un_list(flow.ip_dest),
                          self.un_list(flow.port_dest),
                          'accept' if flow.action.to_string() == 'permit' else 'deny',
                          False, 'white'])
        self.id_calculation()

    # used when the save button is clicked
    def on_saving_matrix_flow(self, widget):
        data = ''
        for row in self.liststore:
            data += 'protocol : ' + row[1] + '\n' if row[1] else 'protocol :\n'
            data += 'ip-source : ' + row[2] + '\n' if row[2] else  'ip-source :\n'
            data += 'ip-destination : ' + row[4] + '\n' if row[4] else 'ip-destination :\n'
            data += 'port-src : ' + row[3] + '\n' if row[3] else 'port-src :\n'
            data += 'port-dst : ' + row[5] + '\n' if row[2] else 'port-dst :\n'
            data += 'action : ' + row[6] + '\n' if row[6] else 'action:\n'
            if (row[0] != self.liststore[-1][0]):
                data += '--\n'
        Gtk_Main.Gtk_Main().statusbar.change_message("Saving matrix flow table ...")
        filename = self.save_filechooser("Save matrix flow")
        if not filename:
            return

        f = open(filename, 'w')
        f.write(data)
        f.close()
        with open(filename) as f:
            print f.read()
        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    # the filechooser for saving file
    def save_filechooser(self, name):
        """Open a file chooser for saving a file.

        Parameters
        ----------
        name : string. The title name of the file chooser dialog

        Return
        ------
        Return the file name to save the file"""
        dialog = gtk.FileChooserDialog(name,
                                       None,
                                       gtk.FILE_CHOOSER_ACTION_SAVE,
                                       (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                        gtk.STOCK_SAVE, gtk.RESPONSE_OK))
        dialog.set_default_response(gtk.RESPONSE_OK)

        last_folder = dialog.get_current_folder()
        if last_folder:
            dialog.set_current_folder(last_folder)
        response = dialog.run()
        filename = None
        if response == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
            self.last_folder = dialog.get_current_folder()
        dialog.destroy()
        return filename

    def fromDotted2Dec(self, ipaddr):
        return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

    def fromDec2Dotted(self, mask):
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return inet_ntoa(pack('>I', bits))


    #### ______init_______ ####
    ## Parameers :
    #  flowlist : a list containing all different flows to test
    #  firewall : the firewall instance on wich the matrix verification
    #  is going to be performed.

    def __init__(self, flowlist, firewall):
        #the liststore wich will contains all the flows
        self.liststore = gtk.ListStore(str, str, str, str, str, str, str, bool, str)

        #the treeview
        self.treeview = gtk.TreeView(self.liststore)

        #different renderers of type text
        self.cellId = gtk.CellRendererText()
        self.cellId.set_property('editable', True)
        self.cellId.set_property('xalign', 0.5)
        self.cellId.connect('edited', self.on_modify_value, self.liststore, 0)

        self.cellProto = gtk.CellRendererText()
        self.cellProto.set_property('editable', True)
        self.cellProto.set_property('xalign', 0.5)
        self.cellProto.connect('edited', self.on_modify_value, self.liststore, 1)

        self.cellIp_src = gtk.CellRendererText()
        self.cellIp_src.set_property('editable', True)
        self.cellIp_src.set_property('xalign', 0.5)
        self.cellIp_src.connect('edited', self.on_modify_value, self.liststore, 2)

        self.cellPort_src = gtk.CellRendererText()
        self.cellPort_src.set_property('editable', True)
        self.cellPort_src.set_property('xalign', 0.5)
        self.cellPort_src.connect('edited', self.on_modify_value, self.liststore, 3)

        self.cellIp_dst = gtk.CellRendererText()
        self.cellIp_dst.set_property('editable', True)
        self.cellIp_dst.set_property('xalign', 0.5)
        self.cellIp_dst.connect('edited', self.on_modify_value, self.liststore, 4)

        self.cellPort_dst = gtk.CellRendererText()
        self.cellPort_dst.set_property('editable', True)
        self.cellPort_dst.set_property('xalign', 0.5)
        self.cellPort_dst.connect('edited', self.on_modify_value, self.liststore, 5)

        self.cellAction = gtk.CellRendererText()
        self.cellAction.set_property('editable', True)
        self.cellAction.connect('edited', self.on_modify_value, self.liststore, 6)

        self.cellSelected = gtk.CellRendererToggle()
        self.cellSelected.set_property("activatable", True)
        self.cellSelected.connect('toggled', self.on_selected, self.liststore, 7)


        # different type of columns of our table
        self.columnId = gtk.TreeViewColumn('Id', self.cellId, text=0, background=8)
        self.treeview.append_column(self.columnId)
        self.columnId.set_expand(True)

        self.columnProto = gtk.TreeViewColumn('Protocol', self.cellProto, text=1, background=8)
        self.treeview.append_column(self.columnProto)
        self.columnProto.set_expand(True)

        self.columnIp_src = gtk.TreeViewColumn('Source IP', self.cellIp_src, text=2, background=8)
        self.treeview.append_column(self.columnIp_src)
        self.columnIp_src.set_expand(True)

        self.columnPort_src = gtk.TreeViewColumn('Source Port', self.cellPort_src, text=3, background=8)
        self.treeview.append_column(self.columnPort_src)
        self.columnPort_src.set_expand(True)

        self.columnIp_dst = gtk.TreeViewColumn('Destination IP', self.cellIp_dst, text=4, background=8)
        self.treeview.append_column(self.columnIp_dst)
        self.columnIp_dst.set_expand(True)

        self.columnPort_dst = gtk.TreeViewColumn('Destination Port', self.cellPort_dst, text=5, background=8)
        self.treeview.append_column(self.columnPort_dst)
        self.columnPort_dst.set_expand(True)

        self.columnAction = gtk.TreeViewColumn('Action', self.cellAction, text=6, background=8)
        self.treeview.append_column(self.columnAction)
        self.columnId.set_expand(False)

        self.columnSelected = gtk.TreeViewColumn('', self.cellSelected)
        self.columnSelected.add_attribute(self.cellSelected, 'active', 7)
        self.columnSelected.set_fixed_width(1)
        self.treeview.append_column(self.columnSelected)

        self.lastColumn = gtk.TreeViewColumn('')
        self.lastColumn.set_expand(False)
        self.lastColumn.set_fixed_width(1)
        self.treeview.append_column(self.lastColumn)


        self.add_flows_to_table(flowlist)

        self.scrolled = gtk.ScrolledWindow()
        self.scrolled.add(self.treeview)
        self.vbox = gtk.VBox()
        self.hbox = gtk.HBox()
        self.hbox1 = gtk.HBox()
        self.vbox1 = gtk.VBox()

        self.buttonAdd = gtk.Button('Add')
        self.buttonAdd.connect('clicked', self.add_empty_row)

        self.buttonRemove = gtk.Button('Remove')
        self.buttonRemove.connect('clicked', self.remove_selected_rows)

        self.buttonSave = gtk.Button('Save')
        self.buttonSave.connect('clicked', self.on_saving_matrix_flow)

        self.buttonLaunch = gtk.Button('Launch')
        self.buttonLaunch.connect('clicked', self.launch_verification)
        self.vbox.pack_start(self.hbox)
        self.vbox.pack_start(self.hbox1)

        self.table = gtk.Table(10, 20, True)
        self.table.attach(self.scrolled, 0, 16, 0, 5)
        self.table.attach(self.buttonAdd, 17, 19, 1, 2)
        self.table.attach(self.buttonRemove, 17, 19, 2, 3)
        self.table.attach(self.buttonSave, 17, 19, 3, 4)
        self.table.attach(self.buttonLaunch, 17, 19, 5, 6)

        self.hbox.pack_start(self.table)

        self.flows = []
        self.firewall = firewall ## remember to change it in firewall (receive in parameter)
        self.result = {}


        ### Begining of showing results

        self.treeview1 = gtk.TreeView()





        '''
        iter1 = self.liststore.append(['1', 'tcp', '192.168.10.0', '45213', '10.0.0.8', '80',
                                       'accept', False, 'white'])
        self.liststore.append(['2', 'tcp', '192.168.10.0', '74', '10.0.0.8', '52', 'accept', False, 'white'])
        self.liststore.append(['2', 'tcp', '192.168.10.0', '74', '10.0.0.8', '52', 'accept', False, 'white'])
        self.liststore.append(['3', 'udp', '192.168.12.0', '585', '10.0.0.8', '51', 'accept', False, 'white'])
        self.liststore.append(['4', 'tcp', '192.168.145.0', '713', '10.0.0.8', '25', 'accept', False, 'white'])
        self.liststore.append(['5', 'icmp', '192.168.10.0', '', '10.0.0.8', '', 'accept', False, 'white'])
        self.liststore.append(['6', 'tcp', '18.0.0.0', '45213', '10.0.0.8', '161', 'accept', False, 'white'])
        acl = ACL('main')

        r0 = Rule(0, 'rule-0', [],
          [Operator('EQ', Ip('192.168.10.0', '255.255.255.0'))], [],
          [Operator('EQ', Ip('192.168.20.0', '255.255.255.0'))], [], Action(False))

        r1 = Rule(1, 'rule-1', [Operator('EQ', Protocol('tcp'))], [],
                  [], [Operator('EQ', Ip('10.0.0.0', '255.255.255.0'))], [Operator('EQ', Port('domain'))],
                  Action('False'))

        r2 = Rule(2, 'rule-2', [Operator('EQ', Protocol('tcp'))],
                  [Operator('EQ', Ip('192.168.0.0', '255.255.255.0'))], [], [], [], Action(False))

        r3 = Rule(3, 'rule-3', [Operator('EQ', Protocol('tcp'))], [],
                  [], [Operator('EQ', Ip('10.0.0.0', '255.255.255.0'))], [Operator('EQ', Port('domain'))],
                  Action('False'))

        rules = []
        rules.append(r0)
        #rules.append(r1)
        #rules.append(r2)
        #rules.append(r3)
        acl.rules = list(rules)
        #self.firewall.acl.append(acl)
        #self.liststore.append(['0', '', '192.168.10.0','', '192.168.20.12', '', 'deny', False, 'white'])

        req = Rule(0, 'rule-0', [],
                  [Operator('EQ', Ip('192.168.10.0', '255.255.255.0'))], [],
                  [Operator('EQ', Ip('192.168.20.0', '255.255.255.0'))], [], Action(True))
        '''