#! /usr/bin/env python
# -*- coding: utf-8 -*-

import matplotlib.pyplot as plt
from matplotlib.offsetbox import OffsetImage, AnnotationBbox
from matplotlib.cbook import get_sample_data
import SpringBase.Firewall as Firewall
import SpringBase.Ip as Ip
from SpringBase.Route_info import Route_info
import os
import NetworkGraph


######## Modification of the class by Maurice TCHAMGOUE N. on 08-07-2015
###          * Adding some informations to show routes on the topology

class Node:
    """Node class.
    The Node class is used to attach an object to a node of the networkX graph.
    A node contains all necessary information to draw it.
    It also contains event listener from matplotlib.

    Parameters
    ----------
    object : Firewall or Ip. An instance of Firewall or Ip depending which element the node represent
    x : float. abscissa
    y : float. ordinate
    img_path : string. image BASE NAME to draw for the node
    zoom : float. Scale of the image
    plot : maplotlib point.
    annotation_box : maplotlib. used for drawing and manipulating image
    text : maplotlib. Used to add information to the node
    note : matplotlib, Used to add information to the node
    fontsize : int. The font size of the text
    artitst : matplotlib. Artist for event listener
    press : bool. Check if node is pressed
    gtk_press : bool. Used for interfacing gtk, True if node is pressed
    over : bool. True if mouse is over the node
    marker : matplotlib. Marker for query path
    marker_type : string. Nature of the marker (possible values : 'from', 'to')
    """
    def __init__(self, object, x=0, y=0):
        self.object = object
        self.x = x
        self.y = y
        if isinstance(object, Firewall.Firewall):
            fn = os.path.join(os.path.dirname(__file__), '../ressources/firewall.png')
            self.img_path = fn
            self.color = 'red'
            self.zoom = 0.2
        elif isinstance(object, Ip.Ip):
            fn = os.path.join(os.path.dirname(__file__), '../ressources/network.png')
            self.color = 'blue'
            self.img_path = fn
            self.zoom = 0.4
        else:
            fn = os.path.join(os.path.dirname(__file__), '../ressources/gateway.png')
            self.color = 'blue'
            self.img_path = fn
            self.zoom = 0.2
        self.plot = None
        self.annotation_box = None
        self.text = None
        self.note = None
        self.note_text = None
        self.fontsize = 8
        self.artist = None
        self.press = False
        self.gtk_press = False
        self.over = False
        self.marker = None
        self.marker_type = None

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['plot']
        del state['annotation_box']
        del state['text']
        del state['note']
        del state['artist']
        del state['marker']
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.plot = None
        self.annotation_box = None
        self.text = None
        self.note = None
        self.artist = None
        self.marker = None

    def on_pick(self, event):
        """Event listener : picker.
        update self.press and self.gtk_press value.
        """
        if self.artist.contains(event.mouseevent)[0] and not NetworkGraph.NetworkGraph().node_click:
            self.gtk_press = True
            if event.mouseevent.button == 1:
                NetworkGraph.NetworkGraph().node_click = True
                self.press = True
                for edge in NetworkGraph.NetworkGraph().graph.edges(self.object, True):
                    edge[2]['object'].press = True
                    if ((edge[2]['object'].x[0] - self.x)**2 + (edge[2]['object'].y[0] - self.y)**2)\
                            < ((edge[2]['object'].x[1] - self.x)**2 + (edge[2]['object'].y[1] - self.y)**2):
                        edge[2]['object'].press_i = 0
                    else:
                        edge[2]['object'].press_i = 1

    def on_motion(self, event):
        """Event listener : motion.
        Update drawn object and position
        """
        if event.xdata and event.ydata:
            if self.press:
                self.x = event.xdata
                self.y = event.ydata
                self.plot.set_data(self.x, self.y)
                self.artist.xytext = (self.x, self.y)
                self.artist.xy = (self.x, self.y)
                if self.text is not None:
                    self.text.set_position((self.x, self.y))
                if self.note is not None:
                    self.note.set_position((self.x, self.y + 0.03))
                if self.marker is not None:
                    self.marker.xytext = (self.x, self.y)
                    self.marker.xy = (self.x, self.y)
            contain = self.artist.contains(event)[0]
            if contain and not self.over:
                self.over = True
                self.zoom_object(True)
                if self.text is not None:
                    self.text.set_visible(True)
            elif not contain and self.over:
                self.over = False
                self.zoom_object(False)
                if self.text is not None:
                    if isinstance(self.object, Firewall.Firewall):
                        self.text.set_visible(NetworkGraph.NetworkGraph().show_fw)
                    elif isinstance(self.object, Route_info):
                        self.text.set_visible(False)
                    else:
                        self.text.set_visible(NetworkGraph.NetworkGraph().show_network)

    def on_release(self, event):
        """Event listener : release.
        Set self.gtk_press and self.press to False
        """
        if self.press:
            NetworkGraph.NetworkGraph().node_click = False
            self.press = False
        self.gtk_press = False

    def zoom_object(self, zoom):
        self.annotation_box.get_children()[0].set_zoom(self.zoom * (1.4 if zoom else 1.))

    def add_image(self, color):
        """Draw an image

        Parameters
        ----------
        color : string. specify the color of the image to draw.
        The concatenation of the self.img_path and the color will give the complete path to the image.
        (ex: to draw a network in blue, self.img_path should='../ressources/network.png' and color='blue')
        """
        if self.artist:
            self.artist.remove()
        self.color = color
        file_name, ext = os.path.splitext(self.img_path)
        new_path = file_name + color + ext
        image_path = get_sample_data(new_path)
        image = plt.imread(image_path)
        im = OffsetImage(image, zoom=self.zoom)
        ab = AnnotationBbox(im, (self.x, self.y), xycoords='data', frameon=False)
        ab.set_picker(5)
        self.artist = plt.gca().add_artist(ab)
        self.annotation_box = ab

    def add_note(self, text):
        """Add a box containing some text.

        Parameters
        ----------
        text : string. The text to add
        """
        if self.note:
            self.note.remove()
            self.note = None
        if len(text) == 0:
            return
        res = ""
        count = 0
        # split text to add return line each 3 words
        for i in text.split(' '):
            res += i
            count += 1
            res += "\n" if count % 3 == 0 else " "
        bbox_props = dict(boxstyle="round", fc="w", ec="0.5", alpha=0.8)
        self.note_text = text
        self.note = plt.gca().text(self.x, self.y + 0.03, res, va="center", size=8, bbox=bbox_props)
        self.note.set_zorder(4)

    def add_marker(self, type):
        """Add a marker and draw it.
        If a node as already the marker type, the marker is deleted and added on the new node.
        If both marker type exist the return value is not None.

        Parameters
        ----------
        type : string. Type of marker (values : 'from', 'to')

        Return
        ------
        Return a tuple of Ip instance if both marker ('from' and 'to') exist else return None.
        """
        both_marker = None

        # parse node list and update marker
        for node in NetworkGraph.NetworkGraph().graph.nodes(data=True):
            if node[1]['object'].marker is not None:
                if node[1]['object'].marker_type == type:
                    node[1]['object'].clear_marker()
                elif self.marker is not None and node[1]['object'].marker == self.marker:
                    node[1]['object'].clear_marker()
                elif type == 'from':
                    both_marker = (self.object, node[1]['object'].object)
                else:
                    both_marker = (node[1]['object'].object, self.object)

        if type == 'from':
            fn = os.path.join(os.path.dirname(__file__), '../ressources/pointA.png')
        else:
            fn = os.path.join(os.path.dirname(__file__), '../ressources/pointB.png')

        image_path = get_sample_data(fn)
        image = plt.imread(image_path)
        im = OffsetImage(image, zoom=self.zoom * 1.4)
        ab = AnnotationBbox(im, (self.x, self.y), xycoords='data', frameon=False)

        self.marker = plt.gca().add_artist(ab)
        self.marker.set_zorder(5)
        self.marker_type = type

        return both_marker

    def clear_marker(self):
        """Remove the marker."""
        if self.marker:
            self.marker.remove()
            self.marker = None
            self.marker_type = None

    def remove(self):
        """Clean the node."""
        if self.plot:
            self.plot.remove()
        if self.text:
            self.text.remove()
        if self.artist:
            self.artist.remove()
        if self.marker:
            self.marker.remove()
        if self.note:
            self.note.remove()
            self.note = None

    def draw(self, canvas):
        """Draw node element and add matplotlib listener.

        Parameters
        ----------
        canvas : A gtk canvas to draw the node element.
        """
        if self.plot is None:
            self.plot, = plt.gca().plot(self.x, self.y)
        if isinstance(self.object, Firewall.Firewall):
            self.plot.set_marker('p')
            self.plot.set_markerfacecolor('red')
            self.add_image(self.color)
        else:
            self.plot.set_marker('o')
            self.plot.set_markerfacecolor('blue')
            self.add_image(self.color)
        self.plot.set_zorder(2)
        self.plot.set_visible(False)
        self.plot.set_data(self.x, self.y)

        if self.text is None:
            if isinstance(self.object, Firewall.Firewall):
                self.text = plt.gca().text(self.x, self.y, self.object.hostname)
                self.text.set_color('#00DDDD')
                self.text.set_fontsize(self.fontsize * 1.25)
                self.text.set_visible(NetworkGraph.NetworkGraph().show_fw)
            if isinstance(self.object, Ip.Ip):
                text = Ip.Ip.toString(self.object.ip & self.object.mask) + " / " + str(Ip.Ip.MaskToCidr(self.object.mask))
                self.text = plt.gca().text(self.x, self.y, text)
                self.text.set_fontsize(self.fontsize)
                self.text.set_visible(NetworkGraph.NetworkGraph().show_network)
            if isinstance(self.object, Route_info):
                self.text = plt.gca().text(self.x, self.y, '')
                self.text.set_color('#000000')
                self.text.set_fontsize(self.fontsize * 1.25)
                self.text.set_visible(False)
            self.text.set_ha('center')
            self.text.set_va('center')
            #self.text.set_weight('bold')
            self.text.set_zorder(4)
        self.text.set_position((self.x, self.y))

        if self.marker_type:
            self.add_marker(self.marker_type)
        if self.note_text:
            self.add_note(self.note_text)

        if self.note is not None:
            self.note.set_position((self.x, self.y + 0.03))
        if self.marker is not None:
            self.marker.xytext = (self.x, self.y)
            self.marker.xy = (self.x, self.y)

        canvas.mpl_connect('pick_event', self.on_pick)
        canvas.mpl_connect('motion_notify_event', self.on_motion)
        canvas.mpl_connect('button_release_event', self.on_release)
