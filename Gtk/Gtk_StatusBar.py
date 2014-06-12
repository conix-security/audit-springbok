#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import gtk


class Gtk_StatusBar:
    """Gtk_StatusBar class.
    An interface for pushing and changing message on a status bar

    Parameters
    ----------
    status_bar : gtk StatusBar
    context_id : the gtk status bar context id
    """
    def __init__(self):
        self.status_bar = gtk.Statusbar()
        self.context_id = self.status_bar.get_context_id("StatusBar")
        self.change_message("Ready")

    def add_message(self, msg):
        """Add a message to the status bar.

        Parameters
        ----------
        msg : string. The message to add
        """
        self.status_bar.push(self.context_id, msg)

    def pop_message(self):
        """Pop a message from the status bar"""
        self.status_bar.pop(self.context_id)

    def change_message(self, msg):
        """Pop the message and add a new one.

        Parameters
        ----------
        msg : string. The message to change
        """
        self.pop_message()
        self.add_message(msg)
