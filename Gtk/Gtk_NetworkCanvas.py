#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
from Gtk import Gtk_HelpMessage

pygtk.require("2.0")
import gtk
from Gtk_NetworkPopupMenu import Gtk_NewtworkPopupMenu
from Gtk_DialogBox import Gtk_DialogBox
from Gtk_HelpMessage import Gtk_Message
from NetworkGraph import NetworkGraph
import Gtk_Main
from matplotlib.backends.backend_gtkagg import FigureCanvasGTKAgg as FigureCanvas
import matplotlib.pyplot as plt
from matplotlib.cbook import get_sample_data
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from SpringBase.Firewall import Firewall
from SpringBase.Ip import Ip
from SpringBase.Route_info import Route_info
from SpringBase.Interface import Interface


class Gtk_NetworkCanvas:
    """Gtk_NetworkCanvas class.
    This class contains the canvas to draw the topology. It implements event listener and zoom.

    Parameters
    ----------
    canvas : the gtk canvas to draw
    adjustement : used for zoom scroll bar
    zoom_scale : a scroll bar to zoom
    redraw : a button to redraw the graph
    popup : a popup for interaction on right click
    bRefresh : bool. if True enable refresh with do_refresh function
    corners : the limit of the canvas drawing area
    press : bool. True if mouse click on canvas (used for zoom)
    x_old, y_old : position for zoom
    """

    def __init__(self):
        fig = plt.figure(num=None, facecolor='w', edgecolor='k')
        plt.axis('off')
        plt.subplots_adjust(left=0., right=1., bottom=0., top=1., wspace=0.2, hspace=0.2)
        self.canvas = FigureCanvas(fig)
        self.canvas.add_events(
            gtk.gdk.EXPOSURE_MASK | gtk.gdk.LEAVE_NOTIFY_MASK | gtk.gdk.BUTTON_PRESS_MASK | gtk.gdk.POINTER_MOTION_MASK | gtk.gdk.POINTER_MOTION_HINT_MASK | gtk.gdk.BUTTON_RELEASE_MASK)
        self.canvas.connect("motion_notify_event", self.on_motion)
        self.canvas.connect("button-press-event", self.on_click)
        self.canvas.connect("button-release-event", self.on_release)
        self.canvas.connect("scroll-event", self.on_scroll)
        self.canvas.connect("leave-notify-event", self.on_lose_focus)

        self.adjustement = gtk.Adjustment(0.0, 0.0, 100.0, 1.0, 1.0, 1.0)
        self.adjustement_signal = self.adjustement.connect("value-changed", self.on_zoom_changed)
        self.zoom_scale = gtk.HScale(self.adjustement)
        self.zoom_scale.set_draw_value(False)
        self.zoom_value = 0.0

        self.redraw = gtk.Button("Redraw")
        self.redraw.connect("clicked", self.on_redraw)

        self.hbox = gtk.HBox()
        self.hbox.pack_start(self.zoom_scale, True, True, 0)
        self.hbox.pack_end(self.redraw, False, False, 0)

        self.vbox = gtk.VBox()
        self.vbox.pack_start(self.canvas, True, True, 0)
        self.vbox.pack_end(self.hbox, False, False, 0)

        self.popup = Gtk_NewtworkPopupMenu()
        self.bRefresh = True
        self.corners = None
        self.press = False
        self.x_old = 0
        self.y_old = 0

        self.bg_img = None
        self.i = 1

    def on_click(self, widget, event):
        """Event listener : click
        If double left click :
        - on edge, show edges rules
        - on firewall, show firewall conf
        - on interface, add note
        If left click :
        - on edge, show message
        - on firewall, show message interaction firewall
        - on interface, show message interaction interface
        - else move x/y limit drawing area
        If right click :
        - on edge, show edge menu
        - on firewall, show firewall menu
        - on interface, show interface menu
        - else show canvas menu
        """
        if event.button == 1 and event.type == gtk.gdk._2BUTTON_PRESS:
            dbl_click = False
            dbl_click |= self.on_dblclick_edge()
            dbl_click |= self.on_dblclick_node()
            if not dbl_click:
                Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.TOPOLOGY_MESSAGE)
        if event.button == 3 and event.type == gtk.gdk.BUTTON_PRESS:
            right_click = False
            right_click |= self.on_right_click_edge(event)
            right_click |= self.on_right_click_node(event)
            if not right_click:
                Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_BACKGROUND_CLICK)
                self.popup.popup_clear(event)
        if event.button == 1 and event.type == gtk.gdk.BUTTON_PRESS:
            left_click = False
            left_click |= self.on_left_click_edge()
            left_click |= self.on_left_click_node()
            if not left_click:
                self.press = True
                self.x_old = event.x
                self.y_old = event.y
                Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.TOPOLOGY_MESSAGE)
        return True

    def on_dblclick_edge(self):
        """Show interface rules"""
        def get_firewall(x, y):
            if isinstance(x, Firewall):
                return x
            elif isinstance(y, Firewall):
                return y
            return None

        def get_ip(x, y):
            if isinstance(x, Ip):
                return x
            elif isinstance(y, Ip):
                return y
            return None

        g = NetworkGraph.NetworkGraph()
        for elem in g.graph.edges(data=True):
            edge = elem[2]['object']
            if edge.gtk_press:
                fw = get_firewall(elem[0], elem[1])
                ip = get_ip(elem[0], elem[1])
                result = []
                [result.append(acl) for acl in g.get_acl_list(src=ip, dst=None, firewall=fw)]
                [result.append(acl) for acl in g.get_acl_list(src=None, dst=ip, firewall=fw)]
                if not result:
                    Gtk_DialogBox("No rules found for this interface !")
                [Gtk_Main.Gtk_Main().notebook.add_interface_tab(acl) for acl in result]
                return True
        return False

    def on_dblclick_node(self):
        """Event listener, on double click node, if firewall show conf file else add note"""
        g = NetworkGraph.NetworkGraph()
        for k, v in g.graph.node.items():
            if v['object'].gtk_press and isinstance(v['object'].object, Firewall):
                Gtk_Main.Gtk_Main().notebook.add_conf_tab(v['object'].object.name, v['object'].object.hostname)
                return True
            if v['object'].gtk_press and isinstance(v['object'].object, Ip):
                self.popup.node = v['object']
                self.popup.on_add_note(None)
                return True
        return False

    def on_right_click_edge(self, event):
        """Event listener, on right click edge, popup menu showing acl list of related to this interface"""
        g = NetworkGraph.NetworkGraph()
        for elem in g.graph.edges(data=True):
            edge = elem[2]['object']
            if edge.gtk_press:
                self.popup.popup(elem, event, edge)
                edge.gtk_press = False
                return True
        return False

    def on_right_click_node(self, event):
        """Event listener, on right click node, show popup menu for node"""
        g = NetworkGraph.NetworkGraph()
        for k, v in g.graph.node.items():
            if v['object'].gtk_press:
                self.popup.popup(None, event, v['object'])
                v['object'].gtk_press = False
                return True
        return False
    def on_left_click_node(self):
        """Show node details"""
        g = NetworkGraph.NetworkGraph()
        for k, v in g.graph.node.items():
            if v['object'].gtk_press:
                Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_Message.ON_CLICK_NODE)
                Gtk_Main.Gtk_Main().lateral_pane.details.clear()
                tmp_intf = [e[2]['object'].object for e in g.graph.edges(k, data=True)]
                if isinstance(tmp_intf, Interface):
                    for e in sorted(tmp_intf, key=lambda tmp_intf: tmp_intf.nameif):
                        message = "%s:\n- %s\n- %s" % (e.nameif, e.name, e.network.to_string())
                        for key, value in e.attributes.items():
                            message += "\n- %s : %s" % (key, value)
                        Gtk_Main.Gtk_Main().lateral_pane.details.add_row(message)
                        Gtk_Main.Gtk_Main().lateral_pane.focus_details()
                    return True
                if isinstance(v['object'].object, Route_info):
                    lateral_pane = Gtk_Main.Gtk_Main().lateral_pane
                    notebook_routes = Gtk_Main.Gtk_Main().lateral_pane.notebook_routes
                    treeview_routes = Gtk_Main.Gtk_Main().lateral_pane.routes_tab_treeview
                    scrolled_window = lateral_pane.routes_tab_treeview.scrolled_window
                    data = v['object'].object.data
                    notebook_routes.notebook.set_tab_label(scrolled_window, gtk.Label(
                            'Networks reached by ' + v['object'].object.iface.nameif))
                    treeview_routes.clear()

                    for gateway, networks in data.iteritems():
                        parent = treeview_routes.add_row(None, gateway, foreground='black', background='grey')
                        for network in networks:
                            treeview_routes.add_row(parent, network)

                    if lateral_pane.vpane.get_child1() == lateral_pane.notebook_path.notebook:
                        lateral_pane.vpane.remove(lateral_pane.notebook_path.notebook)
                    elif lateral_pane.vpane.get_child1() == lateral_pane.notebook_details.notebook:
                        lateral_pane.vpane.remove(lateral_pane.notebook_details.notebook)
                    lateral_pane.vpane.pack1(lateral_pane.notebook_routes.notebook, True, False)
                    lateral_pane.vpane.pack2(lateral_pane.help_message.eb, True, False)
                    Gtk_Main.Gtk_Main().hpaned.set_position(4 * Gtk_Main.Gtk_Main().window.get_size()[0] / 5)
                    lateral_pane.vpane.show_all()

        return False

    def on_left_click_edge(self):
        """If left click edge, show help message"""
        g = NetworkGraph.NetworkGraph()
        for edge in g.graph.edges():
            if g.graph[edge[0]][edge[1]]['object'].gtk_press:
                Gtk_Main.Gtk_Main().lateral_pane.help_message.change_message(Gtk_HelpMessage.Gtk_Message.ON_CLICK_EDGE)
                return True
        return False

    def on_motion(self, widget, event):
        """If not click node, then move axis"""
        if self.press and self.corners:
            xlim = list(plt.gca().get_xlim())
            ylim = list(plt.gca().get_ylim())
            x = (self.x_old - event.x) / (1. * self.canvas.window.get_size()[0] / (xlim[1] - xlim[0]))
            y = (event.y - self.y_old) / (1. * self.canvas.window.get_size()[1] / (ylim[1] - ylim[0]))
            self.x_old = event.x
            self.y_old = event.y
            self.axes_move(x, y, x, y)
        self.do_refresh()

    def refresh(self):
        """refresh function. This function is call periodically by do_refresh"""
        self.bRefresh = True

    def do_refresh(self):
        """Update the graph if bRefresh is True"""
        if self.bRefresh:
            self.bRefresh = False
            self.canvas.draw()
            gtk.timeout_add(30, self.refresh)

    def on_release(self, widget, event):
        """Event listener : release"""
        self.press = False

    def on_scroll(self, widget, event):
        """Event listener : scroll. Update zoom"""
        if event.direction == 0 and self.adjustement.get_value() < 99:
            self.adjustement.set_value(self.adjustement.get_value() + 1)
        elif event.direction == 1 and self.adjustement.get_value() > 0:
            self.adjustement.set_value(self.adjustement.get_value() - 1)

    def on_zoom_changed(self, widget):
        """Event listerner : HScale change. Update zoom"""
        if self.corners:
            im = None
            if self.bg_img:
                im = self.bg_img.get_children()[0]
            if widget.value != 0:
                zoom = (self.zoom_value - widget.value) * (self.corners[1][0] - self.corners[0][0]) / 200
                self.axes_zoom(-zoom, -zoom, zoom, zoom)
                if im:
                    dim = min(1. * self.canvas.window.get_size()[0] / len(im.properties()['data'][0]),
                              1. * self.canvas.window.get_size()[1] / len(im.properties()['data']))
                    corners = min(self.corners[1][0] - self.corners[0][0], self.corners[1][1] - self.corners[0][1])
                    im.set_zoom(im.get_zoom() - zoom * 2 * dim / corners)
            else:
                plt.gca().set_xlim((self.corners[0][0], self.corners[1][0]))
                plt.gca().set_ylim((self.corners[0][1], self.corners[1][1]))
                if im:
                    im.set_zoom(min(1. * self.canvas.window.get_size()[0] / len(im.properties()['data'][0]),
                                    1. * self.canvas.window.get_size()[1] / len(im.properties()['data'])))
            self.zoom_value = widget.value
            self.do_refresh()

    def on_lose_focus(self, widget, event):
        """Event listener : focus"""
        self.press = False
        NetworkGraph.NetworkGraph().node_click = False
        for node in NetworkGraph.NetworkGraph().graph.nodes(data=True):
            node[1]['object'].press = False
        for edge in NetworkGraph.NetworkGraph().graph.edges(data=True):
            edge[2]['object'].press = False
        self.do_refresh()

    def on_redraw(self, widget):
        """Event listener : button redraw"""
        self.draw()

    def axes_move(self, x0, y0, x1, y1):
        """Change axis position according to the drawing area limit.

        Parameters
        ----------
        x0 : float. x minimal value
        x1 : float. x maximal value
        y0 : float. y minimal value
        y1 : float. y maximal value
        """
        if self.corners:
            x = list(plt.gca().get_xlim())
            y = list(plt.gca().get_ylim())
            if ((x0 < 0 and x[0] + x0 >= self.corners[0][0]) or (x0 > 0 and x[0] + x0 < x[1])) and \
                    ((x1 > 0 and x[1] + x1 <= self.corners[1][0]) or (x1 < 0 and x[1] + x1 > x[0])):
                x[0] += x0
                x[1] += x1
            if ((y0 < 0 and y[0] + y0 >= self.corners[0][1]) or (y0 > 0 and y[0] + y0 < y[1])) and \
                    ((y1 > 0 and y[1] + y1 <= self.corners[1][1]) or (y1 < 0 and y[1] + y1 > y[0])):
                y[0] += y0
                y[1] += y1
            plt.gca().set_xlim((x[0], x[1]))
            plt.gca().set_ylim((y[0], y[1]))

    def axes_zoom(self, x0, y0, x1, y1):
        """Zoom axis position according to the drawing area limit.

        Parameters
        ----------
        x0 : float. x minimal value
        x1 : float. x maximal value
        y0 : float. y minimal value
        y1 : float. y maximal value
        """
        if self.corners:
            x = list(plt.gca().get_xlim())
            y = list(plt.gca().get_ylim())
            if (x0 < 0 and x[0] >= self.corners[0][0]) or (x0 > 0 and x[0] + x0 < x[1]):
                x[0] += x0
            if (x1 > 0 and x[1] <= self.corners[1][0]) or (x1 < 0 and x[1] - x1 > x[0]):
                x[1] += x1
            if (y0 < 0 and y[0] >= self.corners[0][1]) or (y0 > 0 and y[0] + y0 < y[1]):
                y[0] += y0
            if (y1 > 0 and y[1] <= self.corners[1][1]) or (y1 < 0 and y[1] - y1 > y[0]):
                y[1] += y1
            plt.gca().set_xlim((x[0], x[1]))
            plt.gca().set_ylim((y[0], y[1]))

    def background_image(self, file):
        """Set the file image as background image"""
        if self.bg_img:
            self.bg_img.remove()

        datafile = get_sample_data(file)
        img = plt.imread(datafile)
        im = OffsetImage(img)
        im.set_zoom(min(1. * self.canvas.window.get_size()[0] / len(im.properties()['data'][0]),
                        1. * self.canvas.window.get_size()[1] / len(im.properties()['data'])))
        self.bg_img = AnnotationBbox(im, (0.5, 0.5), xycoords='data', frameon=False)
        self.bg_img.set_zorder(-1)
        plt.gca().add_artist(self.bg_img)
        self.do_refresh()

    def draw(self):
        """Draw the netowrk graph and set limit corners"""
        g = NetworkGraph.NetworkGraph()
        g.layout_graph()
        g.draw(self.canvas)

        self.corners = (-0.05, -0.05), (1.05, 1.05)
        plt.gca().set_xlim((-0.05, 1.05))
        plt.gca().set_ylim((-0.05, 1.05))

        self.do_refresh()