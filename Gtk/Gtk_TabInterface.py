#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
import re
from Gtk.Gtk_HelpMessage import Gtk_Message

pygtk.require("2.0")
import gtk
import gobject
import Gtk_Main
from SpringBase.Operator import Operator


class Gtk_TabInterface:
    """Gtk_TabInterface class.
    A interface to construct the list view of interface rules
    """
    def __init__(self, name, object):
        """Initialize a new page interface

        Parameters
        ----------
        name : string. The name of the page
        object : object. An object instance (used for dictionary who prevent page duplication)
        """
        self.object = object
        self.scrolled_window = gtk.ScrolledWindow()
        self.scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.model = gtk.ListStore(gobject.TYPE_INT,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING,
                                   gobject.TYPE_STRING)
        self.model_sort = gtk.TreeModelSort(self.model)
        # self.model_sort.set_sort_column_id(0, gtk.SORT_ASCENDING)
        self.tree_view = gtk.TreeView(self.model_sort)
        self.add_column()
        self.scrolled_window.add(self.tree_view)
        self.row_reordered_signal = self.model_sort.connect("rows-reordered", self.on_reordered)
        self.tree_view.connect('cursor-changed', self.on_cursor_changed)

        self.button = gtk.Button("X")
        self.button.set_size_request(22, 15)
        self.button.connect("clicked", self.on_tab_close)

        self.hbox = gtk.HBox()
        self.hbox.pack_start(gtk.Label(name), True, True, 0)
        self.hbox.pack_end(self.button, False, False, 0)
        self.hbox.show_all()

    def search(self, pattern):
        """Search function. Clear list view and add only matching rows

        Parameters
        ----------
        pattern : string. The pattern to match
        """
        result = set()

        if re.search(pattern, 'any'):
            result |= set([rule for rule in self.object.rules if
                            not rule.ip_source or not rule.ip_dest or not rule.port_source or not rule.port_dest])
        if re.search(pattern, 'ip'):
            result |= set([rule for rule in self.object.rules if not rule.protocol])
        if re.search(pattern, 'permit'):
            result |= set([rule for rule in self.object.rules if rule.action])
        if re.search(pattern, 'deny'):
            result |= set([rule for rule in self.object.rules if not rule.action])
        result |= set([rule for rule in self.object.rules if rule.search(pattern)])
        self.model.clear()
        self.add_rules(list(result))

    def on_tab_close(self, widget):
        """Close the interface."""
        notebook = Gtk_Main.Gtk_Main().notebook.notebook
        Gtk_Main.Gtk_Main().notebook.tab_dict.pop(self.object)
        if self.object in Gtk_Main.Gtk_Main().notebook.export_tab:
            Gtk_Main.Gtk_Main().notebook.export_tab.pop(self.object)
        notebook.remove_page(notebook.page_num(self.scrolled_window))

    def on_reordered(self, treemodel, path, iter, new_order):
        """Event listener : rows-reordered.
        Sort the list view and adjust background color based on new position"""
        self.model_sort.handler_block(self.row_reordered_signal)
        for i in range(len(self.model)):
            for j in range(len(self.model)):
                if self.model[j][0] == self.model_sort[i][0]:
                    self.model[j][9] = '#FFFFFF' if i % 2 == 0 else '#DCDCDC'
        self.model_sort.handler_unblock(self.row_reordered_signal)

    def on_cursor_changed(self, tree_view):
        """Event listener : cursor-changed.
        When a row is selected, resolve dictionary name and show numerical value
        """
        if not tree_view.get_selection().get_selected()[1]:
            return

        index = self.model_sort[tree_view.get_selection().get_selected()[1]][0]
        rule = None

        for r in self.object.rules:
            if r.identifier == index:
                rule = r
                break

        if rule:
            Gtk_Main.Gtk_Main().lateral_pane.details.clear()
            protocol = "Protocol :\n" + '\n'.join([s.to_string() for s in rule.protocol]) + "\n"
            ip_src = "Ip source :\n" + '\n'.join([s.to_string() for s in rule.ip_source]) + "\n"
            port_src = "Port source :\n" + '\n'.join([s.to_string() for s in rule.port_source]) + "\n"
            ip_dst = "Ip destination :\n" + '\n'.join([s.to_string() for s in rule.ip_dest]) + "\n"
            port_dst = "Port destination :\n" + '\n'.join([s.to_string() for s in rule.port_dest]) + "\n"
            Gtk_Main.Gtk_Main().lateral_pane.details.add_row(protocol)
            Gtk_Main.Gtk_Main().lateral_pane.details.add_row(ip_src)
            Gtk_Main.Gtk_Main().lateral_pane.details.add_row(port_src)
            Gtk_Main.Gtk_Main().lateral_pane.details.add_row(ip_dst)
            Gtk_Main.Gtk_Main().lateral_pane.details.add_row(port_dst)
            Gtk_Main.Gtk_Main().lateral_pane.focus_details()

        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_SELECT_RULE)

    def add_rules(self, rules):
        """Add a rule to the list with the correct colors.

        Parameters
        ----------
        rules : Rule. The rule to add
        """
        self.model_sort.handler_block(self.row_reordered_signal)
        i = len(self.model)
        format_protocol_int = lambda s: 'ip' if not s else '\n'.join(map(Operator.to_string, s))
        format_protocol = lambda s, n: '\n'.join(set(n)) if n else format_protocol_int(s)
        format_int = lambda s: "any" if len(s) == 0 else '\n'.join(map(Operator.to_string, s))
        format = lambda s, n: '\n'.join(set(n)) if n else format_int(s)
        for r in rules:
            self.model_sort.get_model().append([r.identifier,
                                                r.name,
                                                format_protocol(r.protocol, r.protocol_name),
                                                format(r.ip_source, r.ip_source_name),
                                                format(r.port_source, r.port_source_name),
                                                format(r.ip_dest, r.ip_dest_name),
                                                format(r.port_dest, r.port_dest_name),
                                                "permit" if r.action else "deny",
                                                'darkgreen' if r.action else 'darkred',
                                                '#FFFFFF' if i % 2 == 0 else '#DCDCDC'])
            i += 1
        self.model_sort.handler_unblock(self.row_reordered_signal)

    def add_column(self):
        """Init column for the list view"""
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("ID", cell, text=0, foreground=8, background=9)
        column.set_sort_column_id(0)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Name", cell, text=1, foreground=8, background=9)
        column.set_sort_column_id(1)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Protocol", cell, text=2, foreground=8, background=9)
        column.set_sort_column_id(2)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Ip source", cell, text=3, foreground=8, background=9)
        column.set_sort_column_id(3)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Port source", cell, text=4, foreground=8, background=9)
        column.set_sort_column_id(4)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Ip dest", cell, text=5, foreground=8, background=9)
        column.set_sort_column_id(5)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Port dest", cell, text=6, foreground=8, background=9)
        column.set_sort_column_id(6)
        self.tree_view.append_column(column)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn("Action", cell, text=7, foreground=8, background=9)
        column.set_sort_column_id(7)
        self.tree_view.append_column(column)
