#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import gtk
import ntpath
import time
import cPickle as pickle
from Parser import Parser
from NetworkGraph import NetworkGraph
from SpringBase.ACL import ACL
from AnomalyDetection.InternalDetection import InternalDetection
import Gtk_Main
from Gtk_DialogBox import Gtk_DialogBox
from Gtk_HelpMessage import Gtk_Message
import Gtk_QueryPath
from AnomalyDetection.DistributedDetection import DistributedDetection
from SpringBase.Firewall import Firewall
from SpringBase.Ip import Ip
from SpringBase.Route_info import Route_info
from Parser.MatrixFlowParser.MatrixFlowParser import MatrixFlowParser
from Parser.QueryPathParser.QueryPathParser import QueryPathParser
import Gtk_FwSelect
from socket import *
from socket import inet_ntoa
from struct import pack
import networkx as nx
import os
from Tools.ExcelToolKit import ExcelToolKit
import re

######## Modification of the class by Maurice TCHAMGOUE N.
###          * Adding of some menu to manage the matrix flow verification
###          * Adding a menu to show routes on the topology

class Gtk_MenuBar:
    """Gtk_MenuBar class.
    This class contains all methods for the menubar :
     - importing new firewall conf file
     - open project
     - save project
     - launch query path
     - launch distributed anomaly detection
     - export results
     - view options
     - exit
    """
    def __init__(self):
        self.last_folder = None
        self.next_file = False
        self.tmp_fw_list = []
        self.actives_fw = []

        # use to memorize the tab name (for compliance) #
        self.filenames = []

        # File #
        self.submenu_file = gtk.Menu()

        # Import #
        self.menu_import = gtk.MenuItem("Import configuration")
        self.submenu_file.append(self.menu_import)
        self.menu_import.connect("activate", lambda x: self.menu_file_import())

        # Open project #
        self.menu_open = gtk.MenuItem("Open project")
        self.submenu_file.append(self.menu_open)
        self.menu_open.connect("activate", self.on_open_project)

        # Save project #
        self.menu_save = gtk.MenuItem("Save project")
        self.submenu_file.append(self.menu_save)
        self.menu_save.connect("activate", self.on_save_project)

        # Extract rules to excel #
        self.menu_extract_excel = gtk.MenuItem("Extract rules to excel")
        self.submenu_file.append(self.menu_extract_excel)
        self.menu_extract_excel.connect("activate", self.on_extract_excel)

        # Generate Matrix Table #
        self.menu_matrix_table = gtk.MenuItem("Generate Matrix Table")
        self.submenu_file.append(self.menu_matrix_table)
        self.menu_matrix_table.connect("activate", self.on_generate_matrix)

        # Quit #
        self.menu_quit = gtk.MenuItem("Quit")
        self.submenu_file.append(self.menu_quit)
        self.menu_quit.connect("activate", lambda x: gtk.main_quit())

        self.menu_file = gtk.MenuItem("File")
        self.menu_file.set_submenu(self.submenu_file)


        # Audit #
        self.submenu_audit = gtk.Menu()

        # Distributed detection #
        self.menu_distributed_anomaly = gtk.MenuItem("Distributed anomaly detection")
        self.submenu_audit.append(self.menu_distributed_anomaly)
        self.menu_distributed_anomaly.connect("activate", self.distributed_anomaly)

        # Query file #
        self.menu_query_file = gtk.MenuItem("Import query file")
        self.submenu_audit.append(self.menu_query_file)
        self.menu_query_file.connect("activate", self.on_query_file_import)

        # Export #
        self.menu_export = gtk.MenuItem("Export result")
        self.submenu_audit.append(self.menu_export)
        self.menu_export.connect("activate", self.on_export)

        self.menu_audit = gtk.MenuItem("Audit")
        self.menu_audit.set_submenu(self.submenu_audit)
        self.menu_audit.connect("activate", self.on_audit)

        # View #
        self.submenu_view = gtk.Menu()

        # Always show firewall name #
        self.menu_show_fw = gtk.CheckMenuItem("Always show firewall name")
        self.submenu_view.append(self.menu_show_fw)
        self.menu_show_fw.connect("activate", self.on_show_firewall_name)

        # Always show network value #
        self.menu_show_net = gtk.CheckMenuItem("Always show network value")
        self.submenu_view.append(self.menu_show_net)
        self.menu_show_net.connect("activate", self.on_show_network_name)

        # Show routes
        self.menu_show_routes = gtk.CheckMenuItem("Show routes")
        self.submenu_view.append(self.menu_show_routes)
        self.menu_show_routes.connect("activate", self.on_show_routes)

        self.menu_view = gtk.MenuItem("View")
        self.menu_view.set_submenu(self.submenu_view)

        # Compliance #
        self.submenu_compliance = gtk.Menu()

        # Import flow matrix #
        self.menu_import_flow_matrix = gtk.MenuItem("Import flow matrix")
        self.submenu_compliance.append(self.menu_import_flow_matrix)
        self.menu_import_flow_matrix.connect("activate", self.on_import_matrix_file)

        self.menu_create_matrix_flow = gtk.MenuItem("Create a blank matrix flow")
        self.submenu_compliance.append(self.menu_create_matrix_flow)
        self.menu_create_matrix_flow.connect("activate", self.on_create_matrix_flow)

        self.menu_compliance = gtk.MenuItem("Compliance")
        self.menu_compliance.set_submenu(self.submenu_compliance)

        # Menu #
        self.menubar = gtk.MenuBar()
        self.menubar.append(self.menu_file)
        self.menubar.append(self.menu_audit)
        self.menubar.append(self.menu_view)
        self.menubar.append(self.menu_compliance)

    def on_create_matrix_flow(self, widget):
        """
            Create a blank matrix flow table. It will
            be filled by the user
        """
        Gtk_Main.Gtk_Main().notebook.add_matrix_flow_tab2([], self.tmp_fw_list, None)

    def on_import_matrix_file(self, widget):
        """"Import matrix flow file and show it in a new window"""

        Gtk_Main.Gtk_Main().statusbar.change_message("Importing matrix flow file ...")

        filename = self.open_filechooser("Import the matrix flow file")
        if not filename:
            Gtk_Main.Gtk_Main().statusbar.change_message("Ready")
            return
        data = open(filename).read()

        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_IMPORT_MATRIX_FLOW)
        self.filenames.append(filename)

        # parse Data
        matrix_flow = MatrixFlowParser(data)
        matrix_flow.parse()
        flowlist = list(matrix_flow.flow_list)

        # Send data to the right controller
        Gtk_Main.Gtk_Main().notebook.add_matrix_flow_tab2(flowlist, self.tmp_fw_list, filename)

    def open_filechooser(self, name, multiple_select=False):
        """Open a file chooser for opening a file.

        Parameters
        ----------
        name : string. the title name of the file chooser dialog
        multiple_select : bool (optional, default=False). If true enable multiple selection

        Return
        ------
        If mulitple_select is true return the list of selected file (or empty list if cancel)
        If mulitple_select is false return the name of the selected file (or None if cancel)
        """
        filename = [] if multiple_select else None

        dialog = gtk.FileChooserDialog(name,
                                       None,
                                       gtk.FILE_CHOOSER_ACTION_OPEN,
                                       (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL,
                                        gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_select_multiple(multiple_select)
        dialog.set_default_response(gtk.RESPONSE_OK)
        if self.last_folder:
            dialog.set_current_folder(self.last_folder)

        response = dialog.run()
        if response == gtk.RESPONSE_OK:
            self.last_folder = dialog.get_current_folder()
            if multiple_select:
                filename = dialog.get_filenames()
            else:
                filename = dialog.get_filename()
        dialog.destroy()
        return filename

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
        if self.last_folder:
            dialog.set_current_folder(self.last_folder)

        response = dialog.run()

        filename = None

        if response == gtk.RESPONSE_OK:
            filename = dialog.get_filename()
            self.last_folder = dialog.get_current_folder()
        dialog.destroy()

        return filename

    def on_generate_matrix(self, widget):
        """
        Create a Matrix of flow Table in the output file with the current Fw load
        """
        start_line = 2
        start_col = 2
        if len(self.tmp_fw_list) == 0:
            return
        Gtk_Main.Gtk_Main().statusbar.change_message("Generating Matrix...")
        filename = os.path.dirname(os.path.abspath(__file__)) + "/../input/template_matrix_table.xlsx"
        toolkit = ExcelToolKit(filename, os.path.dirname(os.path.abspath(__file__)) + "/../Tools/tmp_file/")
        toolkit.unzip_file()
        toolkit.select_sheet(1)
        for fw in self.tmp_fw_list:
            for acl in fw.acl:
                if len(acl.rules):
                    for rule in acl.rules:
                        rule_string = rule.to_string_list()
                        # search if ip_source or dest in the table
                        ip_source_coord = toolkit.get_coord_from_value(rule_string[5])
                        ip_dest_coord = toolkit.get_coord_from_value(rule_string[9])
                        ip_source_line = None
                        ip_dest_col = None
                        if len(ip_source_coord):
                            for ip_source in ip_source_coord:
                                ip_source_line = re.search(r'\d+', ip_source).group()
                                ip_source_col = ip_source[:ip_source.index(ip_source_line)]
                                if ip_source_col != toolkit.colnum_string(start_col):
                                    ip_source_line = None
                                else:
                                    break
                        if len(ip_dest_coord):
                            for ip_dest in ip_dest_coord:
                                ip_dest_line = re.search(r'\d+', ip_dest).group()
                                ip_dest_col = ip_dest[:ip_dest.index(ip_dest_line)]
                                if int(ip_dest_line) != start_line:
                                    ip_dest_col = None
                                else:
                                    break
                        if ip_source_line is None:
                            ip_source_line = toolkit.last_line_in_column(start_col)
                            ip_source_line = start_line + 1 if ip_source_line is None else ip_source_line + 1
                            toolkit.set_value(ip_source_line, start_col, rule_string[5])
                        if ip_dest_col is None:
                            ip_dest_col = toolkit.colNameToNum(toolkit.last_column_in_line(start_line))
                            ip_dest_col = start_col + 1 if ip_dest_col is None else ip_dest_col + 1
                            toolkit.set_value(start_line, ip_dest_col, rule_string[9])
                        actual_value = toolkit.get_value(ip_source_line, ip_dest_col)
                        if actual_value is None:
                            actual_value = ""
                        actual_value += "protocol: " + rule_string[2] + ": " + rule_string[3] + "\nport_src: " + \
                                        rule_string[6] + ": " + rule_string[7]
                        actual_value += "\nport_dest: " + rule_string[10] + ": " + rule_string[11] + \
                                        "\naction: " + rule_string[12] \
                                        + "\nfirewall: " + fw.hostname + "\nrule" + str(rule.identifier) + "\n\n"
                        toolkit.set_value(ip_source_line, ip_dest_col, actual_value)
        toolkit.save_sheet()
        toolkit.zip_file(os.path.dirname(os.path.abspath(__file__)) + "/../output/matrix_table.xlsx")
        Gtk_Main.Gtk_Main().statusbar.change_message("Matrix Table ready")
        return

    def menu_file_import(self):
        """Launch a Menu to browse and import files.
        Parse each file.
        Construct ROBDD
        """

        self.tmp_fw_list = []

        Gtk_Main.Gtk_Main().statusbar.change_message("Import ...")

        filenames = self.open_filechooser("Import firewall configuration", multiple_select=True)

        if filenames:
            Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_IMPORT_CONF_FILE)

        while filenames:
            self.file_popup_menu(filenames.pop(0))
            self.next_file = False
            # freeze execution and wait the parser to finish
            while not self.next_file:
                while gtk.events_pending():
                    gtk.main_iteration_do(False)
                time.sleep(0.1)

        # Clean all the fw content
        to_delete_lists = []
        for fw in self.tmp_fw_list:
            to_delete = {}
            for idx1, acl1 in enumerate(fw.acl):
                if len(acl1.rules):
                    if idx1 in to_delete:
                        break
                    for idx2, acl2 in enumerate(fw.acl):
                        if idx1 == idx2:
                            continue
                        if idx2 in to_delete:
                            continue
                        if len(acl2.rules):
                            check = 0
                            if len(acl1.rules) == len(acl2.rules):
                                for idx3, rule in enumerate(acl1.rules):
                                    if acl1.rules[idx3].identifier == acl2.rules[idx3].identifier:
                                        check += 1
                                if check == len(acl1.rules):
                                    to_delete[idx1] = ""
                            else:
                                continue
            to_delete_lists.append(to_delete)
        for idx, to_delete in enumerate(to_delete_lists):
            self.tmp_fw_list[idx].acl = [i for j, i in enumerate(self.tmp_fw_list[idx].acl) if j not in to_delete]

        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.TOPOLOGY_MESSAGE)
        Gtk_Main.Gtk_Main().statusbar.change_message("Construct ROBDD ...")
        Gtk_Main.Gtk_Main().update_interface()
        # Add check for reduce rule number
        for fw in self.tmp_fw_list:
            t0 = time.time()
            fw.build_bdd()
            message = "ROBDD build bdd in %.3f seconds" % (time.time() - t0)
            if len(self.tmp_fw_list) - self.tmp_fw_list.index(fw) - 1 > 0:
                message += ", %d remaining ..." % (len(self.tmp_fw_list) - self.tmp_fw_list.index(fw) - 1)
            Gtk_Main.Gtk_Main().change_statusbar(message)
            Gtk_Main.Gtk_Main().update_interface()

        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    def on_extract_excel(self, widget):
        current_line = 3
        current_col = 2
        if len(self.tmp_fw_list) == 0:
            return
        filename = os.path.dirname(os.path.abspath(__file__)) + "/../input/template_rule_to_excel.xlsx"
        print filename
        toolkit = ExcelToolKit(filename, os.path.dirname(os.path.abspath(__file__)) + "/../Tools/tmp_file/")
        toolkit.unzip_file()
        toolkit.select_sheet(1)
        Gtk_Main.Gtk_Main().statusbar.change_message("Extracting rules...")
        for fw in self.tmp_fw_list:
            for acl in fw.acl:
                if len(acl.rules):
                    for rule in acl.rules:
                        for idx, data in enumerate(rule.to_string_list()):
                            toolkit.set_value(current_line, toolkit.colnum_string(idx+current_col), data)
                        current_line += 1
        Gtk_Main.Gtk_Main().statusbar.change_message("Extract ready")
        toolkit.save_sheet()
        toolkit.zip_file(os.path.dirname(os.path.abspath(__file__)) + "/../output/rule_to_excel.xlsx")
        print toolkit.get_value(1, "A")

    def file_popup_menu(self, filename):
        """Detect firewall type and parse the conf file"""
        def iter_next():
            # unblock file
            self.next_file = True

        Gtk_Main.Gtk_Main().statusbar.change_message("Import %s" % filename)
        progressBar = gtk.ProgressBar(adjustment=None)
        progressBar.set_text("Parsing File")
        progressBar.set_fraction(0)

        vbox = gtk.VBox()
        vbox.pack_start(progressBar)

        button_radio = []
        for p in Parser.parser_list:
            tmp_radio = gtk.RadioButton(button_radio[0][0] if button_radio else None, p[1])
            button_radio.append((tmp_radio, p[0]))
            vbox.pack_start(tmp_radio)

        button_cancel = gtk.Button("Cancel")
        button_start = gtk.Button("Start")
        hbox = gtk.HBox()
        hbox.pack_start(button_cancel)
        hbox.pack_start(button_start)

        popup = gtk.Window()
        popup.set_title(ntpath.basename(filename))
        popup.connect("destroy", lambda x: iter_next())

        popup.set_modal(True)
        popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        popup.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)

        vbox.pack_start(hbox)
        popup.add(vbox)

        popup.show_all()

        supposed_type = Parser.suppose_type(filename)
        for p in button_radio:
            if p[1] == supposed_type:
                p[0].set_active(True)

        def on_click(widget):
            parser_module = 'Parser.CiscoAsa.CiscoAsaYacc'
            for p in button_radio:
                if p[0].get_active():
                    parser_module = p[1]

            firewalls = Parser.parser(filename, parser_module, progressBar)
            for fw in firewalls:
                NetworkGraph.NetworkGraph().network_graph(fw)
                Gtk_Main.Gtk_Main().lateral_pane.firewalls.add_row(fw.hostname)
                Gtk_Main.Gtk_Main().lateral_pane.focus_firewall()
            Gtk_Main.Gtk_Main().draw()
            popup.destroy()
            self.tmp_fw_list += firewalls

        button_start.connect("clicked", on_click)
        button_cancel.connect("clicked", lambda x: popup.destroy())

    def file_popup_menu2(self, filename):
        """Detect firewall type and parse the conf file"""
        def iter_next():
            # unblock file
            self.next_file = True

        Gtk_Main.Gtk_Main().statusbar.change_message("Import %s" % (filename))
        progressBar = gtk.ProgressBar(adjustment=None)
        progressBar.set_text("Parsing File")
        progressBar.set_fraction(0)

        vbox = gtk.VBox()
        vbox.pack_start(progressBar)

        button_radio = []
        for p in Parser.parser_list:
            tmp_radio = gtk.RadioButton(button_radio[0][0] if button_radio else None, p[1])
            button_radio.append((tmp_radio, p[0]))
            vbox.pack_start(tmp_radio)

        button_cancel = gtk.Button("Cancel")
        button_start = gtk.Button("Start")
        hbox = gtk.HBox()
        hbox.pack_start(button_cancel)
        hbox.pack_start(button_start)

        popup = gtk.Window()
        popup.set_title(ntpath.basename(filename))
        popup.connect("destroy", lambda x: iter_next())

        popup.set_modal(True)
        popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        popup.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)

        vbox.pack_start(hbox)
        popup.add(vbox)

        popup.show_all()

        supposed_type = Parser.suppose_type(filename)
        for p in button_radio:
            if p[1] == supposed_type:
                p[0].set_active(True)

        def on_click(widget):
            parser_module = 'Parser.CiscoAsa.CiscoAsaYacc'
            for p in button_radio:
                if p[0].get_active():
                    parser_module = p[1]

            firewalls = Parser.parser(filename, parser_module, progressBar)

            firewalls_list = []
            for fw in firewalls:
                firewalls_list.append(fw)

            if len(firewalls_list) > 1:
                fw_select = Gtk_FwSelect.Gtk_FwSelect()
                fw_select.firewalls_list = firewalls_list
                self.actives_fw = list(fw_select.firewalls_list)
                fw_select.buildWindows()
                popup.destroy()
                self.tmp_fw_list += firewalls
            else:
                self.actives_fw = list(firewalls_list)
                for fw in firewalls_list:
                    NetworkGraph.NetworkGraph().network_graph(fw)
                    Gtk_Main.Gtk_Main().lateral_pane.firewalls.add_row(fw.hostname)
                    Gtk_Main.Gtk_Main().lateral_pane.focus_firewall()
                Gtk_Main.Gtk_Main().draw()
                popup.destroy()
                self.tmp_fw_list += firewalls_list

        button_start.connect("clicked", on_click)
        button_cancel.connect("clicked", lambda x: popup.destroy())

    def on_open_project(self, widget):
        """Open project and load saved object"""
        Gtk_Main.Gtk_Main().statusbar.change_message("Open project ...")

        filename = self.open_filechooser("Open project")
        if not filename:
            return

        # clear #
        Gtk_Main.Gtk_Main().lateral_pane.firewalls.clear()
        Gtk_Main.Gtk_Main().lateral_pane.details.clear()
        Gtk_Main.Gtk_Main().lateral_pane.path.clear()
        while Gtk_Main.Gtk_Main().notebook.notebook.notebook.get_n_pages() > 0:
            Gtk_Main.Gtk_Main().notebook.notebook.notebook.remove_page(0)
        while Gtk_Main.Gtk_Main().notebook.notebook_split.notebook.get_n_pages() > 0:
            Gtk_Main.Gtk_Main().notebook.notebook_split.notebook.remove_page(0)
        Gtk_Main.Gtk_Main().notebook.notebook.add_tab(Gtk_Main.Gtk_Main().networkcanvas.vbox, "Topology")
        Gtk_Main.Gtk_Main().notebook.tab_dict.clear()
        for node in NetworkGraph.NetworkGraph().graph.node.items():
            if isinstance(node[0], Firewall):
                NetworkGraph.NetworkGraph().remove_firewall(node[1]['object'])

        fh = open(filename, 'rb')
        p = pickle.Unpickler(fh)

        # get network graph singleton
        NetworkGraph.NetworkGraph._instance = p.load()

        # get saved query path
        [Gtk_Main.Gtk_Main().lateral_pane.path.add_row(m) for m in p.load()]
        Gtk_Main.Gtk_Main().lateral_pane.path_data = p.load()

        # get notebook list
        notebook_list = p.load()
        fh.close()

        # add firewall list
        [Gtk_Main.Gtk_Main().lateral_pane.firewalls.add_row(fw.hostname) for fw in NetworkGraph.NetworkGraph().firewalls]

        # redraw
        Gtk_Main.Gtk_Main().networkcanvas.draw()

        # add notebook page
        for i in notebook_list:
            if isinstance(i, ACL):
                Gtk_Main.Gtk_Main().notebook.add_interface_tab(i)
            elif isinstance(i, InternalDetection):
                Gtk_Main.Gtk_Main().notebook.add_internal_anomaly_tab(i)
            elif isinstance(i, DistributedDetection):
                Gtk_Main.Gtk_Main().notebook.add_distributed_anomaly_tab(i)

        Gtk_Main.Gtk_Main().notebook.notebook.notebook.set_page(0)

        Gtk_Main.Gtk_Main().statusbar.change_message("Construct ROBDD ...")
        firewall_list = NetworkGraph.NetworkGraph().firewalls
        for fw in firewall_list:
            t0 = time.time()
            fw.build_bdd()
            message = "ROBDD build bdd in %.3f seconds" % (time.time() - t0)
            if len(firewall_list) - firewall_list.index(fw) - 1 > 0:
                message += ", %d remaining ..." % (len(firewall_list) - firewall_list.index(fw) - 1)
            Gtk_Main.Gtk_Main().change_statusbar(message)

        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    def on_save_project(self, widget):
        Gtk_Main.Gtk_Main().statusbar.change_message("Save project ...")
        filename = self.save_filechooser("Save project")
        if not filename:
            return

        fh = open(filename, 'wb')
        p = pickle.Pickler(fh, -1)
        # save networkgraph singleton
        p.dump(NetworkGraph.NetworkGraph())
        # save query path
        p.dump([m[0] for m in Gtk_Main.Gtk_Main().lateral_pane.path.model])
        p.dump(Gtk_Main.Gtk_Main().lateral_pane.path_data)
        # save notebook pages
        p.dump([k for k, v in Gtk_Main.Gtk_Main().notebook.tab_dict.items()])
        fh.close()
        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    def on_audit(self, widget):
        """If the current page can be exported, export menu is sensitive"""
        if Gtk_Main.Gtk_Main().notebook.can_export():
            self.menu_export.set_sensitive(True)
        else:
            self.menu_export.set_sensitive(False)

    def distributed_anomaly(self, widget):
        """Launch distributed anomaly and add the result in a new notebook page"""
        def start_detection(popup, deep_search):
            popup.destroy()
            distributed_detection = DistributedDetection(deep_search)
            result = distributed_detection.distributed_detection()

            if not reduce(lambda x, y: x | y, [len(v) > 0 for _, v in result], False):
                Gtk_DialogBox("No error found !")
                return

            Gtk_Main.Gtk_Main().notebook.add_distributed_anomaly_tab(distributed_detection)

        check_button = gtk.CheckButton("Deep search")
        cancel_button = gtk.Button("Cancel")
        cancel_button.connect("clicked", lambda x: popup.destroy())
        start_button = gtk.Button("Start")
        start_button.connect("clicked", lambda x: start_detection(popup, check_button.get_active()))

        hbox = gtk.HBox()
        hbox.pack_start(cancel_button)
        hbox.pack_start(start_button)

        vbox = gtk.VBox()
        vbox.pack_start(check_button)
        vbox.pack_start(hbox)

        popup = gtk.Window()
        popup.set_title("Distributed detection")
        popup.set_modal(True)
        popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        popup.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)
        popup.add(vbox)
        popup.show_all()
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_DEEP_SEARCH)

    def on_query_file_import(self, widget):
        """Import query file and launch all parsed queries"""
        Gtk_Main.Gtk_Main().statusbar.change_message("Import query path file ...")

        filename = self.open_filechooser("Import query path file")
        if not filename:
            Gtk_Main.Gtk_Main().statusbar.change_message("Ready")
            return

        query_path = QueryPathParser(filename)
        result = query_path.parse()
        if result:
            Gtk_DialogBox(result, gtk.MESSAGE_ERROR)
        else:
            query_path.run()
            Gtk_QueryPath.treeview_output(query_path)
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_IMPORT_QUERY_FILE)

    def on_export(self, widget):
        """Export result"""
        Gtk_Main.Gtk_Main().statusbar.change_message("Export results ...")
        filename = self.save_filechooser("Export result")
        if not filename:
            return
        Gtk_Main.Gtk_Main().notebook.export(filename)
        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_EXPORT_RESULT)

    def on_show_firewall_name(self, widget):
        """Checkbox, if true firewall name is always visible"""
        NetworkGraph.NetworkGraph().show_fw = widget.get_active()
        for node in NetworkGraph.NetworkGraph().graph.nodes(data=True):
            if isinstance(node[1]['object'].object, Firewall):
                node[1]['object'].text.set_visible(widget.get_active())
        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()

    def on_show_network_name(self, widget):
        """Checkbox, if true network ip is always visible"""
        NetworkGraph.NetworkGraph().show_network = widget.get_active()
        for node in NetworkGraph.NetworkGraph().graph.nodes(data=True):
            if isinstance(node[1]['object'].object, Ip):
                node[1]['object'].text.set_visible(widget.get_active())
        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()

    def on_show_routes(self, widget):
        """ This method will redraw the topology of the network graph
            by adding routes
        """
        g = NetworkGraph.NetworkGraph().graph
        for node in g.nodes():
            # print node
            if isinstance(node, Firewall):
                print node.route_list
            else:
                pass  # print node.to_string()

        print 'end nodes\n'
        for edge in g.edges(data=True):
            # print edge

            firewall, ip = (edge[0], edge[1]) if isinstance(edge[0], Firewall) and isinstance(edge[1], Ip)\
                else (edge[1], edge[0])
            route_list = firewall.route_list
            iface = self.get_iface_from_ip(firewall, ip)
            routes = []
            for route in route_list:
                if route.iface == iface:
                    routes.append(route)
            output = {}
            for route in routes:
                if route.gw_ip.to_string() in [key for key in output.keys()]:
                    output[route.gw_ip.to_string()].append(route.net_ip_dst.to_string() +
                                                           '/' + str(fromDotted2Dec(route.net_mask.to_string())))
                else:
                    output[route.gw_ip.to_string()] = []
                    tmp = route.net_ip_dst.to_string()
                    tmp2 = route.net_mask.to_string()
                    if tmp == "0.0.0.0 / 0":
                        tmp = "0.0.0.0"
                    if tmp2 == "0.0.0.0 / 0":
                        tmp2 = "0.0.0.0"
                    output[route.gw_ip.to_string()].append(tmp
                                                           + '/' + str(fromDotted2Dec(tmp2)))
            print len(output), output
            if len(output) > 0:
                data = Route_info(output, iface)
                edge[2]['object'].remove()
                NetworkGraph.NetworkGraph()._add_route_info(firewall, data, iface, edge)
                NetworkGraph.NetworkGraph.multidigraph = nx.MultiGraph()
                Gtk_Main.Gtk_Main().lateral_pane.focus_firewall()
                Gtk_Main.Gtk_Main().draw()

    def listContains(route_list, ip_dest):
        for route in route_list:
            if ip_dest.ip & route.net_ip_dst.ip & route.net_ip_dst.mask == \
                                    ip_dest.ip & route.net_ip_dst.mask & ip_dest.mask:
                return route
            return None

    def on_format_route_output(self):
        """
        To print gateways and destinations network in a right way
        """

    def get_iface_from_ip(self, firewall, ip):
        for iface in firewall.interfaces:
            if ip != None and iface.network != None:
                if iface.network.to_string() == ip.to_string():
                    return iface
        print firewall.hostname, ip.to_string()
        return

# The following two functions are used to convert an IP address from it
# dotted format to the decimal one and vice-versa

def fromDotted2Dec(ipaddr):
    return sum([bin(int(x)).count('1') for x in ipaddr.split('.')])

def fromDec2Dotted(mask):
    bits = 0xffffffff ^ (1 << 32 - mask) - 1
    return inet_ntoa(pack('>I', bits))

