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


class Gtk_NoteBookSplit:
    """Gtk_NoteBookSplit class.
    This class contains two notebooks used for splitting tab.

    Parameters
    ----------
    notebook : Gtk_NoteBook. The first notebook
    notebook_split : Gtk_NoteBook. The second notebook for splitting

    tab_dict : dict. Dictionary of referenced tabs (used to not reopen these tabs)
    export_tab : dict. Dictionary tab who can be exported
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
            self.tab_interface.add_rules(obj.rules)
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
