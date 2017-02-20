#! /usr/bin/env python
# -*- coding: utf-8 -*-

import matplotlib.pyplot as plt
import math
import NetworkGraph
from SpringBase.Interface import Interface
from SpringBase.Route_info import Route_info

######## Modification of the class by Maurice TCHAMGOUE N. on the 08-07-2015
###          * Adding some informations to link gateways with the correponding firewall
###          * Adding a menu to show routes on the topology


class Edge:
    """Edge class.
    The edge class is used to attach informations to the edge of the networkX graph.
    An edge instance contains information about the represented interface and the firewall of the interface.

    Parameters
    ----------
    object : Interface. An instance to the corresponding interface
    firewall : Firewall. An instance to the corresponding Firewall
    x : float. abscissa
    y : float. ordinate
    line : matplotlib line
    path : matplotlib line used to show query path
    text : text of the line
    line_width : width of the line. Proportional with the number of rule in the interface.
    fontsize : int. Size font of the text
    over : bool. True if the mouse is over the line
    press : bool. True if the line is pressed
    contain : bool. True if the line is contained
    gtk_press : bool. Used for gtk_interface.
    """
    def __init__(self, object, firewall):
        self.object = object
        self.firewall = firewall
        self.data = firewall
        self.x = []
        self.y = []
        self.line = None
        self.path = None
        self.has_path = False
        self.text = None
        self.line_width = 1
        self.fontsize = 8
        self.over = False
        self.press = False
        self.press_i = 0
        self.contain = False
        self.gtk_press = False

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['line']
        del state['path']
        del state['text']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.line = None
        self.path = None
        self.text = None
        if self.has_path:
            self.mark_path()

    def on_press(self, event):
        """Event listener : press"""
        if self.over:
            self.gtk_press = True

    def on_motion(self, event):
        """Event listener : motion
        Update position of drawn objects"""
        if event.xdata is not None and event.ydata is not None:
            if self.press:
                self.x[self.press_i] = event.xdata
                self.y[self.press_i] = event.ydata
                self.line.set_data(self.x, self.y)
                if self.path is not None:
                    self.path.set_data(self.x, self.y)
                self.text.set_position(((self.x[0] + self.x[1]) / 2, (self.y[0] + self.y[1]) / 2))
            self.contain = self.line_contains(event)
            if self.contain and not reduce(lambda x, y: x | y, [n[1]['object'].over for n in
                                                                NetworkGraph.NetworkGraph().graph.nodes(data=True)],
                                                                False):
                self.line.set_color('black')
                self.line.set_linewidth(self.line_width * 1.2)
                self.text.set_weight('bold')
                self.over = True
            else:
                self.line.set_color('grey')
                self.line.set_linewidth(self.line_width)
                self.text.set_weight('normal')
                self.over = False

    def on_release(self, event):
        """Event listener : release"""
        if self.press:
            self.press = False
            self.press_i = 0
        self.gtk_press = False

    def line_contains(self, event, teta=0.01):
        """Detect if the mouse is over the line.

        Parameters
        ----------
        teta : float (optional, default=0.01). Approximation value.

        Return
        ------
        Return True if the distance between the line and the mouse is lower than teta else return False.
        """
        if self.x[0] < self.x[1] and (event.xdata < self.x[0] or event.xdata > self.x[1]):
            return False
        if self.x[0] > self.x[1] and (event.xdata > self.x[0] or event.xdata < self.x[1]):
            return False
        if self.y[0] < self.y[1] and (event.ydata < self.y[0] or event.ydata > self.y[1]):
            return False
        if self.y[0] > self.y[1] and (event.ydata > self.y[0] or event.ydata < self.y[1]):
            return False

        a = self.y[1] - self.y[0]
        b = self.x[0] - self.x[1]
        c = self.x[1] * self.y[0] - self.x[0] * self.y[1]
        d = math.fabs(a * event.xdata + b * event.ydata + c) / math.sqrt(a * a + b * b)
        return d < teta

    def mark_path(self):
        """Add a colored line over the existing line. Used for query path"""
        self.has_path = True

        if self.path is not None:
            return

        self.path, = plt.gca().plot(self.x, self.y)
        self.path.set_zorder(2)
        self.path.set_label(self.object.to_string())
        self.path.set_color('blue')
        self.path.set_alpha(0.5)
        self.path.set_linewidth(self.line_width * 1.7)

    def mark_path2(self):
        """Add a colored line over the existing line. Used for query path"""
        self.has_path = True

        if self.path is not None:
            return

        self.path, = plt.gca().plot(self.x, self.y)
        self.path.set_zorder(2)
        self.path.set_label(self.object.to_string())
        self.path.set_color('cyan')
        self.path.set_alpha(0.5)
        self.path.set_linewidth(self.line_width * 1.7)

    def clear_path(self):
        """Remove the colored line. Used for query path"""
        self.has_path = False
        if self.path is not None:
            self.path.remove()
            self.path = None

    def remove(self):
        """Clear the edge"""
        self.clear_path()
        if self.line:
            self.line.remove()
        if self.text:
            self.text.remove()

    def draw(self, canvas):
        """Draw edge element and add matplotlib listener.

        Parameters
        ----------
        canvas : a gtk canvas to draw the edge element.
        """
        if self.line is None:
            self.line, = plt.gca().plot(self.x, self.y)
            self.line.set_zorder(1)
            self.line.set_color('grey')
            self.line.set_linewidth(self.line_width)
        self.line.set_data(self.x, self.y)

        if self.text is None:
            text_posx = (self.x[0] + self.x[1]) / 2
            text_posy = (self.y[0] + self.y[1]) / 2
            if isinstance(self.object, Interface):
                self.text = plt.gca().text(text_posx, text_posy, self.object.short_name())
            elif isinstance(self.object, Route_info):
                self.text = plt.gca().text(text_posx, text_posy, self.object.iface.nameif)### remember to manage this
            self.text.set_fontsize(self.fontsize)
            self.text.set_ha('center')
            self.text.set_va('center')
            self.text.set_backgroundcolor('white')
            self.text.set_zorder(5)
        self.text.set_position(((self.x[0] + self.x[1]) / 2, (self.y[0] + self.y[1]) / 2))

        if self.path is not None:
            self.path.set_data(self.x, self.y)

        canvas.mpl_connect('button_press_event', self.on_press)
        canvas.mpl_connect('motion_notify_event', self.on_motion)
        canvas.mpl_connect('button_release_event', self.on_release)
