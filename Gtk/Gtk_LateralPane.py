#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import gtk
import Gtk_NoteBook
import Gtk_ListView
import Gtk_TreeView
import Gtk_Main
import Gtk_HelpMessage
from NetworkGraph import NetworkGraph


######## Modification of the class by Maurice TCHAMGOUE N. on 29-06-2015
###          * Adding a Path routed list : wich will contains all static
###            routed path
###


class Gtk_LateralPane():
    """Gtk_LateralPane class.
    This class contains all necessary elements of the lateral pane :
    - Firewall list
    - Details
    - Path (for query path)

    Parameters
    ----------
    notebook_details : notebook for the details lateral pane
    firewalls : list view of firewalls
    details : list view of  details
    button_details : a button to show/hide details section
    path : a list view of path
    button_path : a button to show/hide path section
    """
    def __init__(self):
        # Notebook Details #
        self.notebook_details = Gtk_NoteBook.Gtk_NoteBook()
        # Tab Details #
        self.firewalls = Gtk_ListView.Gtk_ListView("Firewall List")
        self.firewalls.tree_view.connect('cursor-changed', self.on_firewall_change)
        self.firewalls.tree_view.connect('row-activated', self.on_firewall_row_activated)
        self.details = Gtk_ListView.Gtk_ListView("Details")
        self.notebook_details.add_tab(self.firewalls.scrolled_window, "Firewall List", True)
        self.notebook_details.add_tab(self.details.scrolled_window, "Details", True)
        # Button details #
        self.button_details = gtk.Button('\n'.join("Details"))
        self.button_details.connect("clicked", self.on_click_details)
        self.button_details.set_size_request(22, 150)
        # help message #
        self.help_message = Gtk_HelpMessage.Gtk_HelpMessage()

        # ListView Path #
        self.notebook_path = Gtk_NoteBook.Gtk_NoteBook()

        self.path = Gtk_ListView.Gtk_ListView("Path List", True)
        self.path.tree_view.connect('cursor-changed', self.on_cursor_changed)
        self.path.tree_view.connect('row-activated', self.on_path_row_activated)

        self.path_data = None

        self.path_route = Gtk_ListView.Gtk_ListView("Routed Paths", True)
        self.path_route.tree_view.connect('cursor-changed', self.on_cursor_changed2)
        self.path_route.tree_view.connect('row-activated', self.on_path_row_activated2)

        # Notebook Routes
        self.notebook_routes = Gtk_NoteBook.Gtk_NoteBook()

        # Tab Routes
        self.routes_tab_treeview = Gtk_TreeView.Gtk_TreeView('Routes')
        self.notebook_routes.add_tab(self.routes_tab_treeview.scrolled_window, 'Routes', True)




        # Button Routes
        self.button_routes = gtk.Button('\n'.join('Routes'))
        self.button_routes.connect('clicked', self.on_clicked_routes)
        self.button_routes.set_size_request(22, 150)




        self.notebook_path.add_tab(self.path.scrolled_window, "Path List", True)
        self.notebook_path.add_tab(self.path_route.scrolled_window, "Routed Paths", True)

        # Button Path #
        self.button_path = gtk.Button('\n'.join("Path"))
        self.button_path.connect("clicked", self.on_click_path)
        self.button_path.set_size_request(22, 150)

        # VBox #
        self.vbox = gtk.VBox()
        self.vbox.pack_start(self.button_details, False, False)
        self.vbox.pack_start(self.button_path, False, False)
        self.vbox.pack_start(self.button_routes, False, False)

        # HPaned #
        self.vpane = gtk.VPaned()
        self.vpane.pack1(self.notebook_details.notebook, True, False)
        self.vpane.pack2(self.help_message.eb, True, False)
        self.vpane.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)

        # HBox #
        self.hbox = gtk.HBox()
        self.hbox.pack_start(self.vpane, True, True)
        self.hbox.pack_start(self.vbox, False, False)

    def rename_routes_tab(self, new_name):

        # Tab Routes
        self.notebook_routes.notebook.remove_page(0)
        self.routes_tab_treeview = Gtk_TreeView.Gtk_TreeView(new_name)
        self.notebook_routes.add_tab(self.routes_tab_treeview.scrolled_window, new_name, True)


    def on_clicked_routes(self, widget):
        """Event listener : click Routes button
        Show/hide the Routes section and hide the path / details section"""
        if self.vpane.get_child1() == self.notebook_routes.notebook:
            self.vpane.remove(self.notebook_routes.notebook)
            self.vpane.remove(self.help_message.eb)
            Gtk_Main.Gtk_Main().hpaned.set_position(
                Gtk_Main.Gtk_Main().window.get_size()[0] - self.button_routes.get_allocation().width)
        else:
            if self.vpane.get_child1() == self.notebook_path.notebook:
                self.vpane.remove(self.notebook_path.notebook)
            elif self.vpane.get_child1() == self.notebook_details.notebook:
                self.vpane.remove(self.notebook_details.notebook)
            self.vpane.pack1(self.notebook_routes.notebook, True, False)
            self.vpane.pack2(self.help_message.eb, True, False)
            Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.vpane.show_all()

    def on_click_details(self, widget):
        """Event listener : click details button
        Show/hide the details section and hide the path section"""
        if self.vpane.get_child1() == self.notebook_details.notebook:
            self.vpane.remove(self.notebook_details.notebook)
            self.vpane.remove(self.help_message.eb)
            Gtk_Main.Gtk_Main().hpaned.set_position(
                Gtk_Main.Gtk_Main().window.get_size()[0] - self.button_details.get_allocation().width)
        else:
            if self.vpane.get_child1() == self.notebook_path.notebook:
                self.vpane.remove(self.notebook_path.notebook)
            elif self.vpane.get_child1() == self.notebook_routes.notebook:
                self.vpane.remove(self.notebook_routes.notebook)
            self.vpane.pack1(self.notebook_details.notebook, True, False)
            self.vpane.pack2(self.help_message.eb, True, False)
            Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.vpane.show_all()

    def on_click_path(self, widget):
        """Event listener : click path button
        Show/hide the path section and hide the details section"""
        if self.vpane.get_child1() == self.notebook_path.notebook:
            self.vpane.remove(self.notebook_path.notebook)
            self.vpane.remove(self.help_message.eb)
            Gtk_Main.Gtk_Main().hpaned.set_position(
                Gtk_Main.Gtk_Main().window.get_size()[0] - self.button_path.get_allocation().width)
        else:
            if self.vpane.get_child1() == self.notebook_details.notebook:
                self.vpane.remove(self.notebook_details.notebook)
            elif self.vpane.get_child1() == self.notebook_routes.notebook:
                self.vpane.remove(self.notebook_routes.notebook)
            self.vpane.pack1(self.notebook_path.notebook, True, False)
            self.vpane.pack2(self.help_message.eb, True, False)
            Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.vpane.show_all()

    def on_click_path2(self, widget):
        """Event listener : click path button
        Show/hide the path section and hide the details section"""
        if self.vpane.get_child1() == self.path.scrolled_window:
            self.vpane.remove(self.notebook_path.notebook)
            self.vpane.remove(self.help_message.eb)
            Gtk_Main.Gtk_Main().hpaned.set_position(
                Gtk_Main.Gtk_Main().window.get_size()[0] - self.button_path.get_allocation().width)
        else:
            if self.vpane.get_child1() == self.notebook_details.notebook:
                self.vpane.remove(self.notebook_details.notebook)
            self.vpane.pack1(self.notebook_path.notebook, True, False)
            self.vpane.pack2(self.help_message.eb, True, False)
            Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.vpane.show_all()

    def on_firewall_change(self, tree_view):
        """Event listener : firewall selection
        Raise when a firewall is selected in the firewall list :
        - add extra information to this firewall
        - thick the firewall on the topology
        """
        if not tree_view.get_selection().get_selected()[1]:
            return

        index = self.firewalls.model.get_path(tree_view.get_selection().get_selected()[1])[0]

        firewalls = NetworkGraph.NetworkGraph().firewalls

        for i in xrange(len(firewalls)):
            if i == index:
                nb_rules = firewalls[index].get_nb_rules()
                self.firewalls.model[i][0] = "{0:s}\n{1:s}\nnumber of rules : {2:d}".format(firewalls[i].hostname,
                                                                                            firewalls[i].name, nb_rules)
                NetworkGraph.NetworkGraph().graph.node[firewalls[i]]['object'].zoom_object(True)
            else:
                self.firewalls.model[i][0] = "%s" % firewalls[i].hostname
                NetworkGraph.NetworkGraph().graph.node[firewalls[i]]['object'].zoom_object(False)

        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()

    def on_firewall_row_activated(self, tree_view, iter, path):
        """Event listener : firewall activation
        On activation (double click) of a row in the firewalls list, show the firewall in a new tab"""
        if not tree_view.get_selection().get_selected()[1]:
            return

        index = self.firewalls.model.get_path(tree_view.get_selection().get_selected()[1])[0]
        firewalls = NetworkGraph.NetworkGraph().firewalls
        Gtk_Main.Gtk_Main().notebook.add_conf_tab(firewalls[index].name, firewalls[index].hostname)

    def on_cursor_changed(self, tree_view):
        """Event listener : path selection
        Raise when a path is selected in the path section.
        Update the topology and mark the edge with the selected path"""
        index = self.path.model.get_path(tree_view.get_selection().get_selected()[1])[0]

        if index >= len(self.path_data):
            return

        highlight_path = self.path_data[index][0]
        i = 1
        g = NetworkGraph.NetworkGraph()

        for edge in g.graph.edges(data=True):
            edge[2]['object'].clear_path()

        while i < len(highlight_path):
            edge = g.graph[highlight_path[i - 1]][highlight_path[i]]['object']
            edge.mark_path()
            i += 1

        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Main.Gtk_Message.ON_SELECT_QUERY_PATH)

    def on_cursor_changed2(self, tree_view):
        """Event listener : path selection
        Raise when a path is selected in the path section.
        Update the topology and mark the edge with the selected path"""
        index = self.path_route.model.get_path(tree_view.get_selection().get_selected()[1])[0]

        if index >= len(self.path_data):
            return

        highlight_path = self.path_data[index][0]
        i = 1
        g = NetworkGraph.NetworkGraph()

        for edge in g.graph.edges(data=True):
            edge[2]['object'].clear_path()

        while i < len(highlight_path):
            edge = g.graph[highlight_path[i - 1]][highlight_path[i]]['object']
            edge.mark_path2()
            i += 1

        Gtk_Main.Gtk_Main().networkcanvas.do_refresh()
        Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Main.Gtk_Message.ON_SELECT_QUERY_PATH)

    def on_path_row_activated(self, tree_view, iter, path):
        """Event listener : path activation
        On activation (double click) of a row in the path section, show the corresponding rule who allowed the path"""
        index = self.path.model.get_path(tree_view.get_selection().get_selected()[1])[0]

        if index >= len(self.path_data):
            return

        rule_list = self.path_data[index][1]
        self.details.clear()
        [self.details.add_row(i[1].to_string()) for i in rule_list]
        self.focus_details()

    def on_path_row_activated2(self, tree_view, iter, path):
        """Event listener : path activation
        On activation (double click) of a row in the path section, show the corresponding rule who allowed the path"""
        index = self.path_route.model.get_path(tree_view.get_selection().get_selected()[1])[0]

        if index >= len(self.path_data):
            return

        rule_list = self.path_data[index][1]
        self.details.clear()
        [self.details.add_row(i[1].to_string()) for i in rule_list]
        self.focus_details()

    def hide_pane(self):
        """Hide the details section"""
        if self.vpane.get_child1() == self.notebook_details.notebook:
            self.vpane.remove(self.notebook_details.notebook)
        if self.vpane.get_child1() == self.path.scrolled_window:
            self.vpane.remove(self.notebook_details.notebook)
        self.vpane.remove(self.help_message.eb)
        Gtk_Main.Gtk_Main().hpaned.set_position(
            Gtk_Main.Gtk_Main().window.get_size()[0] - self.button_path.get_allocation().width)
        self.vpane.show_all()

    def focus_firewall(self):
        """Focus the firewall notebook page in the detail section"""
        if self.vpane.get_child1() == self.path.scrolled_window:
            self.vpane.remove(self.path.scrolled_window)
        if self.vpane.get_child1() != self.notebook_details.notebook:
            self.vpane.pack1(self.notebook_details.notebook, True, False)
        self.vpane.pack2(self.help_message.eb, True, False)
        Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.notebook_details.notebook.set_current_page(0)
        self.vpane.show_all()

    def focus_details(self):
        """Focus the details notebook page in the detail section"""
        if self.vpane.get_child1() == self.path.scrolled_window:
            self.vpane.remove(self.path.scrolled_window)
        if self.vpane.get_child1() != self.notebook_details.notebook:
            self.vpane.pack1(self.notebook_details.notebook, True, False)
        self.vpane.pack2(self.help_message.eb, True, False)
        Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.notebook_details.notebook.set_current_page(1)
        self.vpane.show_all()

    def focus_path(self):
        """Focus the path section"""
        if self.vpane.get_child1() == self.notebook_details.notebook:
            self.vpane.remove(self.notebook_details.notebook)
        if self.vpane.get_child1() != self.path.scrolled_window:
            self.vpane.pack1(self.notebook_path.notebook, True, False)
        self.vpane.pack2(self.help_message.eb, True, False)
        Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
        self.vpane.show_all()