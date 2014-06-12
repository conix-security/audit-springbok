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
from Parser.QueryPathParser.QueryPathParser import QueryPathParser


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

        # File #
        self.submenu_file = gtk.Menu()

        # Import #
        self.menu_import = gtk.MenuItem("Import configuration")
        self.submenu_file.append(self.menu_import)
        self.menu_import.connect("activate", self.menu_file_import)

        # Open project #
        self.menu_open = gtk.MenuItem("Open project")
        self.submenu_file.append(self.menu_open)
        self.menu_open.connect("activate", self.on_open_project)

        # Save project #
        self.menu_save = gtk.MenuItem("Save project")
        self.submenu_file.append(self.menu_save)
        self.menu_save.connect("activate", self.on_save_project)

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

        self.menu_view = gtk.MenuItem("View")
        self.menu_view.set_submenu(self.submenu_view)

        # Menu #
        self.menubar = gtk.MenuBar()
        self.menubar.append(self.menu_file)
        self.menubar.append(self.menu_audit)
        self.menubar.append(self.menu_view)

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

    def menu_file_import(self, widget):
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

        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.TOPOLOGY_MESSAGE)

        Gtk_Main.Gtk_Main().statusbar.change_message("Construct ROBDD ...")

        for fw in self.tmp_fw_list:
            t0 = time.time()
            fw.build_bdd()
            message = "ROBDD build bdd in %.3f seconds" % (time.time() - t0)
            if len(self.tmp_fw_list) - self.tmp_fw_list.index(fw) - 1 > 0:
                message += ", %d remaining ..." % (len(self.tmp_fw_list) - self.tmp_fw_list.index(fw) - 1)
            Gtk_Main.Gtk_Main().change_statusbar(message)

        Gtk_Main.Gtk_Main().statusbar.change_message("Ready")

    def file_popup_menu(self, filename):
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

            firewall = Parser.parser(filename, parser_module, progressBar)
            NetworkGraph.NetworkGraph().network_graph(firewall)
            Gtk_Main.Gtk_Main().lateral_pane.firewalls.add_row(firewall.hostname)
            Gtk_Main.Gtk_Main().lateral_pane.focus_firewall()
            Gtk_Main.Gtk_Main().draw()
            popup.destroy()
            self.tmp_fw_list.append(firewall)

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