#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import gtk
import Gtk_Main


class Gtk_DialogBox:
    """Gtk_DialogBox class. Shorthand for popup window notifications"""
    def __init__(self, message, gtk_message=gtk.MESSAGE_INFO, gtk_button=gtk.BUTTONS_OK):
        self.message = message
        self.gtk_message = gtk_message
        self.gtk_button = gtk_button
        self.run()

    def run(self):
        """Run the dialog Box"""
        md = gtk.MessageDialog(Gtk_Main.Gtk_Main().window,
                               gtk.DIALOG_DESTROY_WITH_PARENT, self.gtk_message,
                               self.gtk_button, self.message)
        md.run()
        md.destroy()
