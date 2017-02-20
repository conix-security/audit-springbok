#!/usr/bin/python
# coding=utf-8
from SpringBase.Rule import Rule
from SpringBase.Ip import Ip
from SpringBase.Action import Action
from SpringBase.Port import Port
from SpringBase.Protocol import Protocol
from SpringBase.Operator import Operator
from ROBDD.synthesis import synthesize
from ROBDD.operators import Bdd
from ROBDD.synthesis import compare


r0 = Rule(0, 'rule-0', [],
          [Operator('EQ', Ip('192.168.10.0', '255.255.255.0'))], [],
          [Operator('EQ', Ip('192.168.20.0', '255.255.255.0'))], [], Action('False'))

r1 = Rule(1, 'rule-1', [Operator('EQ', Protocol('tcp'))], [],
          [], [Operator('EQ', Ip('10.0.0.0', '255.255.255.0'))], [Operator('EQ', Port('domain'))],
          Action('False'))

r2 = Rule(0, 'rule-0', [Operator('EQ', Protocol('tcp'))],
          [Operator('EQ', Ip('192.168.0.0', '255.255.255.0'))], [], [], [], Action('False'))

r3 = Rule(1, 'rule-1', [Operator('EQ', Protocol('tcp'))], [],
          [], [Operator('EQ', Ip('10.0.0.0', '255.255.255.0'))], [Operator('EQ', Port('domain'))],
          Action('False'))

#print r0.to_string()
#print r1.to_string()

req = Rule(0, 'rule-0', [],
          [Operator('EQ', Ip('192.168.10.0'))], [],
          [Operator('EQ', Ip('192.168.20.12'))], [], Action('True'))

###print req.to_string()

def is_subset(rule, test_rule):
    """return True if rule is a subset of test_rule, false otherwise (use ROBDD)"""
    return len(synthesize(test_rule.toBDD(), Bdd.IMPL, rule.toBDD()).items) <= 2

#print r0.action.to_string()
#print req.action.to_string()
#print r0.action.to_string() == req.action.to_string()
print r0.to_string(), req.to_string()
if is_subset(r0, req) and r0.action.to_string() != req.action.to_string():
    print 'pb'





'''

#! /usr/bin/python
#encoding:utf8

import sys
import gtk
import pygtk
pygtk.require('2.0')

class Example:
    def close_meth(self):
        print 'ferméture...'
        gtk.main_quit()
        return False

    # To add a new row in the matrix table
    def add_row(self, liststore, elements=None):
        if not elements:
            liststore.append()
        else:
            liststore.append(elements)

    #to remove an element in the matrix table (by its reference)
    def remove_row(self, liststore, ref):
        liststore.remove(ref)

    # to clear the whole matrix tab
    def clear_liststore(self, liststore):
        liststore.clear()

    # to retrieve data in a cell
    def get_one_value(self, liststore, iter, column):
        return liststore.get_value(iter, column)


    #def get_all_values(self, liststore, iter, columns):
    #    return liststore.get(iter, [column for column in columns])

    # to update datas when modified by the user
    def on_modify_value(self, cellrenderer, path, new_value, liststore, column):
        print "updating '%s' to '%s'" % (liststore[path][column], new_value)
        liststore[path][column] = new_value
        return

    def __init__(self):
        self.fenetre = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.fenetre.set_size_request(500, 500)
        self.fenetre.set_title('Hello you...')
        self.fenetre.connect('delete_event', self.close_meth)

        self.cell = gtk.CellRendererText()
        self.cell.set_property('editable', True)


        self.liststore = gtk.ListStore(int, str, str, str, str, str, str)
        print self.liststore.get_flags()
        iters = []
        iter1 = self.add_row(self.liststore)
        iter2 = self.add_row(self.liststore)
        print type(iter1), iter2
        #gtk.TREE_MODEL_ITERS_PERSIST =






        self.treeview = gtk.TreeView(self.liststore)
        self.fenetre.show()

def main():
    gtk.main()

if __name__ == '__main__':
    test = Example()
    main()
    print test
'''