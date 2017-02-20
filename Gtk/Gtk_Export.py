#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import gtk
import Gtk_QueryPath
import NetworkGraph.NetworkGraph
from Gtk_DialogBox import Gtk_DialogBox
from SpringBase.Firewall import Firewall


class Gtk_Export:
    """Gtk_Export class.
    Used to export to file text an object.
    All export callback function are defined below.

    Parameters
    ----------
    filename : string. The location to save
    callback : object. The cllaback function to export object
    ref : object. The object to export
    """
    '''
        MODIFICATIONS!!!!
            This class has been modified by Maurice TCHAMGOUE NDONGO on the 22-05-2015
            to add the callback save_matrix_flow_table. It will be used to export the
            matrix flow table into a text file
    '''


    def __init__(self, filename, callback, ref):
        self.filename = filename
        self.callback = callback
        self.ref = ref

    def save(self):
        """Try to open the file and launch saving callback function"""
        try:
            fd = open(self.filename, 'w')
        except:
            Gtk_DialogBox('Error while opening the export file', gtk.MESSAGE_ERROR)
            return

        self.callback(fd, self.ref)

        fd.close()


def export_internal_detection(fd, ref):
    """Export internal detection as text file"""
    fd.write(64 * '#' + '\n')
    fd.write('Firewall : %s\n' % ref.firewall.hostname)
    fd.write('At %s\n' % ref.firewall.name)
    fd.write('Number of rules : %s\n' % ref.firewall.get_nb_rules())
    fd.write(64 * '#' + '\n\n')

    for elem in ref.result:
        for error in elem:
            fd.write(error)
            fd.write('\n' + 128 * '-' + '\n')


def export_distributed_detection(fd, ref):
    """Export distributed detection as text file"""
    fd.write(64 * '#' + '\n')
    fd.write('Firewalls :\n')
    for fw in NetworkGraph.NetworkGraph.NetworkGraph().firewalls:
        fd.write('-- Firewall %s\n' % fw.hostname)
        fd.write('     At %s\n' % fw.name)
        fd.write('     Number of rules : %s\n' % fw.get_nb_rules())
    fd.write(64 * '#' + '\n\n')

    for k, v in ref.error_path:
        if len(v) > 0:
            path = "[ "
            for elem in k:
                if isinstance(elem, Firewall):
                    path += elem.hostname
                else:
                    path += elem.to_string()
                if elem != k[-1]:
                    path += ", "
            path += " ]\n"
            fd.write(path)
            for error in v:
                fd.write(4 * ' ' + error + '\n')
                fd.write(128 * '-' + '\n')
        fd.write('\n')


def export_error_configuration(fd, ref):
    """Export configuration anomaly detection as text file"""
    fd.write(64 * '#' + '\n')
    fd.write('Firewall : %s\n' % ref.hostname)
    fd.write('At %s\n' % ref.name)
    fd.write('Number of rules : %s\n' % ref.get_nb_rules())
    fd.write(64 * '#' + '\n\n')

    if ref.unused_objects:
        fd.write("Unused objects :\n")
        for i in ref.unused_objects:
            fd.write("-- %s\n" % i)

    fd.write('\n' + 128 * '-' + '\n\n')

    if ref.unbounded_rules:
        fd.write("Unbounded rules :\n")
        for i in ref.unbounded_rules:
            fd.write("-- %s\n" % i)


def export_query_path(fd, ref):
    """Export query path result as text file"""
    result = ref.result
    fd.write(32 * '#' + '\n')
    fd.write("Query Path Import\n")
    fd.write(32 * '#' + '\n\n')
    for i in result:
        rule = i[0]
        path_data = i[1]
        fd.write(rule.to_string(' ') + '\n')
        if isinstance(path_data, str):
            fd.write('-- %s\n' % path_data)
            continue
        for data in path_data:
            fd.write('-- %s\n' % Gtk_QueryPath.path_to_string(data[0], ' '))
            for r in data[1]:
                fd.write('---- %s\n' % r[1].to_string(' '))
            fd.write('\n')
        fd.write(128 * '-' + '\n')

def save_matrix_flow_table(fd, ref):
    pass