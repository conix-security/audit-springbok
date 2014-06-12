#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
from Gtk.Gtk_HelpMessage import Gtk_Message
pygtk.require("2.0")
import gtk
import os
import Gtk_MenuBar
import Gtk_NetworkCanvas
import Gtk_LateralPane
import Gtk_NoteBook
import Gtk_StatusBar
import Gtk_ProgressBar


class Gtk_Main(object):
    _instance = None
    """Gtk_Main class.
    Gtk_Main use singleton pattern.
    The main class for gtk interface.
    This class contains all necessary elements for the interface.

    Parameters
    ----------
    window : the window
    menubar : the menu bar
    lateral_pane : the lateral pane
    notebook : the notebook (containing topology, rules list, ...)
    networkcanvas : the network canvas class for the topology
    statusbar : a status bar
    """
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(Gtk_Main, cls).__new__(cls)
            cls._instance.window = None
            if args and args[0] == 'no-graphic':
                cls._instance.graphic = False
            else:
                cls._instance.graphic = True
                cls._instance.init_window()
        return cls._instance

    def init_window(self, h=None, w=None, title="Springbok (beta version)"):
        """Init window and all necessary gtk elements"""
        # Create new window
        self.window = gtk.Window()
        self.window.connect("destroy", lambda x: gtk.main_quit())
        if h is None:
            h = gtk.gdk.screen_height()
        if w is None:
            w = gtk.gdk.screen_width()
        self.window.set_default_size(w, h)
        self.window.set_title(title)
        fn = os.path.join(os.path.dirname(__file__), '../ressources/icon.png')
        self.window.set_icon_from_file(fn)

        ##################### Construct zone #####################
        vbox = gtk.VBox()
        self.window.add(vbox)

        # menu #
        self.menubar = Gtk_MenuBar.Gtk_MenuBar()
        vbox.pack_start(self.menubar.menubar, False, False, 2)

        # hpaned #
        self.hpaned = gtk.HPaned()
        vbox.pack_start(self.hpaned, True, True, 2)

        # listView #
        self.lateral_pane = Gtk_LateralPane.Gtk_LateralPane()
        self.hpaned.pack2(self.lateral_pane.hbox, False, False)

        # notebook #
        self.notebook = Gtk_NoteBook.Gtk_NoteBookSplit()
        self.hpaned.pack1(self.notebook.hpaned, True, False)
        self.hpaned.set_position(4 * self.window.get_size()[0] / 5)

        # canvas #
        self.networkcanvas = Gtk_NetworkCanvas.Gtk_NetworkCanvas()
        self.notebook.add_tab(self.networkcanvas.vbox, "Topology")

        # status bar #
        self.statusbar = Gtk_StatusBar.Gtk_StatusBar()
        vbox.pack_end(self.statusbar.status_bar, False, False)

        ###############################################################

        self.window.show_all()
        self.lateral_pane.focus_firewall()

        # Add event for notebook #
        self.notebook.notebook.do_connect()
        self.notebook.notebook_split.do_connect()

        self.count = 0
        self.progress_bar = None

        gtk.main()

    def draw(self):
        """Draw the topology"""
        self.networkcanvas.draw()

    def update_interface(self):
        """periodically update interface when asked"""
        if self.graphic:
            if not self.count % 10:
                while gtk.events_pending():
                    gtk.main_iteration_do(False)
            self.count += 1 % 10

    def change_statusbar(self, message):
        """interface to change status bar message"""
        if self.graphic:
            self.statusbar.change_message(message)

    def create_progress_bar(self, name, max_value, callable=None, *args):
        """create a progress bar"""
        if self.graphic:
            if self.progress_bar is not None:
                self.progress_bar.destroy()
            self.progress_bar = Gtk_ProgressBar.Gtk_ProgressBar(name, max_value, callable, args)

    def update_progress_bar(self, value):
        """pulse the progress bar"""
        if self.graphic:
            if self.progress_bar:
                self.progress_bar.update(value)

    def destroy_progress_bar(self):
        """destroy the progress bar"""
        if self.graphic:
            if self.progress_bar:
                self.progress_bar.destroy()