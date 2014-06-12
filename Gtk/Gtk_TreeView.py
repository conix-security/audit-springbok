#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
import Gtk_Main

pygtk.require("2.0")
import gtk


class Gtk_TreeView():
    """Gtk_TreeView class.
    An interface for gtk treeview usage with adding/removing methods.
    """
    def __init__(self, name, header_visible=False):
        """Initialize a new tree view.

        Parameters
        ----------
        name : string. The name of the column
        header_visible : bool (optional, default=False). If True the column header is visible
        """
        self.treestore = gtk.TreeStore(str, str, str)
        self.treeview = gtk.TreeView(self.treestore)
        self.tvcolumn = gtk.TreeViewColumn(name)
        self.treeview.append_column(self.tvcolumn)
        self.treeview.set_headers_visible(header_visible)
        self.treeview.connect("key-press-event", self.on_key_pressed)
        self.treeview.connect("row-activated", self.on_row_activated)
        self.cell = gtk.CellRendererText()
        self.tvcolumn.pack_start(self.cell, True)
        self.tvcolumn.add_attribute(self.cell, 'text', 0)
        self.tvcolumn.add_attribute(self.cell, 'foreground', 1)
        self.tvcolumn.add_attribute(self.cell, 'background', 2)

        self.scrolled_window = gtk.ScrolledWindow()
        self.scrolled_window.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.scrolled_window.add(self.treeview)

    def on_key_pressed(self, widget, event):
        """Key event for tree view.
        - If left arrow or right arrow is pressed, expand/collapse to the current path
        """
        tree_row = self.treeview.get_selection().get_selected()[1]
        if not tree_row:
            return
        if event.keyval == gtk.keysyms.Left:
            current_row = self.treeview.get_model()[self.treeview.get_selection().get_selected()[1]]
            self.treeview.collapse_row(current_row.path)
            self.treeview.set_cursor(current_row.path)
            if current_row.parent:
                self.treeview.collapse_row(current_row.parent.path)
                self.treeview.set_cursor(current_row.parent.path)
        elif event.keyval == gtk.keysyms.Right:
            self.treeview.expand_to_path(self.treeview.get_model()[self.treeview.get_selection().get_selected()[1]].path)

    def on_row_activated(self, treeview, path, viewcolumn):
        """Mouse listener for tree view.
        - If double click on a row, expand/collapse to the selected row
        """
        if self.treeview.row_expanded(path):
            self.treeview.collapse_row(path)
        else:
            self.treeview.expand_to_path(path)

    def clear(self):
        """Remove all element in the treeview"""
        self.treestore.clear()

    def add_row(self, parent, name, foreground='black', background='white'):
        """Add a row under the given parent with the given colors

        Parameters
        ----------
        parent : gtk TreeIter or None. Add the row as a child under the parent if not None else add under the root
        name : string. The string to add
        foreground : string (optional, default='black'). The text color
        background : string (optional, default='white'). The background color

        Return
        ------
        Return a gtk TreeIter pointing to the new row (used for add child under the row)
        """
        return self.treestore.append(parent, [name, foreground, background])
