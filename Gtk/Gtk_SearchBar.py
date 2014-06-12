#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import re
import gtk
import Gtk_Main
from AnomalyDetection.DistributedDetection import DistributedDetection


class Gtk_SearchBar:
    """Gtk_SearchBar class.
    Search bar added on the top of a tab to search result.

    Parameters
    ----------
    ref_object : The referenced object where to search
    gtk_def : the gtk object to modify/add result
    gtk_object : the gtk object to add search bar
    """
    def __init__(self, ref_object, gtk_def, gtk_object):
        self.ref_object = ref_object
        self.gtk_def = gtk_def
        self.gtk_object = gtk_object

        self.hbox = gtk.HBox()
        self.entry = gtk.Entry()
        self.button = gtk.Button("Search")
        self.button.connect("clicked", self.on_search)
        self.hbox.pack_start(self.entry)
        self.hbox.pack_start(self.button, False, False, 2)

        self.vbox = gtk.VBox()
        self.vbox.pack_start(self.hbox, False, False, 2)
        self.vbox.pack_start(self.gtk_object)

    def on_search(self, widget):
        """Event listener. Launch search"""
        if isinstance(self.ref_object, DistributedDetection):
            self.gtk_def.clear()
            Gtk_Main.Gtk_Main().notebook._add_distributed_anomaly(self.ref_object.error_path,
                                                                  self.gtk_def,
                                                                  self.entry.get_text().lower())
        elif isinstance(self.ref_object, gtk.TextView):
            self._conf_highlight()
        else:
            self.gtk_def.search(self.entry.get_text().lower())

    def _conf_highlight(self):
        """Search pattern in the firewall configuration file"""
        textbuffer = self.ref_object.get_buffer()
        tag_table = textbuffer.get_tag_table()
        c_tag = tag_table.lookup("colored")
        if not c_tag:
            c_tag = textbuffer.create_tag("colored", foreground="#000000", background="#FFFF00")
        text = textbuffer.get_text(textbuffer.get_bounds()[0], textbuffer.get_bounds()[1])
        textbuffer.delete(textbuffer.get_bounds()[0], textbuffer.get_bounds()[1])
        for line in re.split(r'\r\n|\r|\n', text):
            for e in re.compile("(" + self.entry.get_text().lower() + ")", re.I).split(line):
                if re.search(self.entry.get_text().lower(), e, re.I):
                    textbuffer.insert_with_tags(textbuffer.get_end_iter(), e, c_tag)
                else:
                    textbuffer.insert_with_tags(textbuffer.get_end_iter(), e)
            textbuffer.insert_with_tags(textbuffer.get_end_iter(), '\n')