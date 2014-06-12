#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk

pygtk.require("2.0")
import gtk
import Gtk_Main
import time


class Gtk_ProgressBar():
    """Gtk_ProgressBar class.
    A class showing a progress bar in a new popup window. (Used for long treatment like anomaly detection)

    Parameters
    ----------
    progress_bar : gtk ProgressBar
    popup : gtk window
    """
    def __init__(self, text, max_value, callable=None, *args):
        self.progress_bar = gtk.ProgressBar(adjustment=None)
        self.progress_bar.set_text(text)
        self.progress_bar.set_fraction(0)

        self.text = text
        self.value = 0
        self.max_value = max_value if max_value else 1
        self.start_time = time.time()

        self.popup = gtk.Window()
        self.popup.set_title("Processing ...")

        self.popup.set_modal(True)
        self.popup.set_transient_for(Gtk_Main.Gtk_Main().window)
        self.popup.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)

        self.vbox = gtk.VBox()
        self.vbox.pack_start(self.progress_bar)

        if callable:
            self.cancel_button = gtk.Button("Cancel")
            self.cancel_button.connect("clicked", callable, args)
            self.popup.connect("destroy", callable, args)
            self.vbox.pack_start(self.cancel_button)

        self.popup.add(self.vbox)

        self.popup.show_all()

    def update(self, value):
        """Update the progress bar"""
        if value == 0:
            return
        self.value += value
        t = time.time() - self.start_time
        self.progress_bar.set_text("%s : %d h %d m %d s" % (self.text, t / 3600, (t % 3600) / 60, t % 60))
        self.progress_bar.set_fraction(1. * self.value / self.max_value)

    def destroy(self):
        """Destroy the window with the progress bar"""
        self.popup.destroy()
