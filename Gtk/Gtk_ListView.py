#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import re
import gtk
import gobject


class Gtk_ListView():
    """Gtk_ListView class.
    This class create a list view in a scrolled window and contains method for adding/deleting row.

    Parameters
    ----------
    name : string. The name of the treeview column
    header_visible : bool (optional, default=False). True if the header column must be visible
    """
    def __init__(self, name, header_visible=False):
        self.scrolled_window = gtk.ScrolledWindow()
        self.scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.model = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.tree_view = gtk.TreeView(self.model)
        self.tree_view.set_headers_visible(header_visible)
        self.scrolled_window.add(self.tree_view)
        cell = gtk.CellRendererText()
        column = gtk.TreeViewColumn(name, cell, text=0, foreground=1, background=2)
        self.tree_view.append_column(column)
        self.elem_list = []

    def search(self, pattern):
        """Clear the model and append only element that match the pattern"""
        self.model.clear()
        [self.model.append(e) for e in self.elem_list if re.search(pattern, e[0], re.I)]

    def clear(self):
        """Clear all element in the list view"""
        self.elem_list = []
        self.model.clear()

    def add_row(self, name, foreground='black', background='white'):
        """Add a row in the list view

        Parameters
        ----------
        name : string. The string row to add.
        foreground : string (optional, default='black'). The text color
        background : string (optional, default='white'). The background color
        """
        self.elem_list.append([name, foreground, background])
        self.model.append([name, foreground, background])
