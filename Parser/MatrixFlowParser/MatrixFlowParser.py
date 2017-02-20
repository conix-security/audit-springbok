#! /usr/bin/env python
# -*- coding: utf-8 -*-

import Parser.MatrixFlowParser.MatrixFlowYacc as matrix_flow_parser
from Parser.MatrixFlowParser.MatrixFlowLex import lexer
import Gtk.Gtk_QueryPath
import Gtk.Gtk_Main
from ROBDD.synthesis import synthesize
from ROBDD.synthesis import Bdd


class MatrixFlowParser:
    """MatrixFlowParser class.
    This class is used to parse query path file and run query path search

    Parameters
    ----------
    - filename : string. The file to parse
    - query_list : Rule list. The list of rule to search
    - result : list. The result list.
    """
    def __init__(self, data):
        self.data = data
        self.flow_list = []
        self.result = {}

    def parse(self):
        """Parse the data receive and send back a list of flaw to test"""
        __import__('os').system("rm parse*")

        f = open('tmp', 'w')
        f.write(self.data)
        f.close()

        try:
            fd = open('tmp', 'r')
        except:
            return 'Error while opening the configuration file'

        matrix_flow_parser.init()

        for line in fd:
            try:
                matrix_flow_parser.parser.parse(line, lexer, debug=0)
            except:
                return 'Error while parsing line: %s' % line

        fd.close()
        self.flow_list = matrix_flow_parser.get_query()
        for rule in self.flow_list:
            print rule.to_string()
        return None


    def run(self, firewalls_list):
        """Perform the matrix flow verification on the selected firewalls
           given in parameters

           Parameters :
            * firewalls_list : intend to be a list containing firewalls
               selected by the user
        """
        res = {}

        Gtk.Gtk_Main.Gtk_Main().create_progress_bar("Matrix Flow import", len(self.flow_list))

        for req in self.flow_list:
            for fw in firewalls_list:
                for acl in fw.acl:
                    for rule in acl.rules:
                        if is_subset(rule, req) == True :#and req.action.to_string() != rule.action.to_string():
                            if res.has_key(req.name):
                                res[req.name].append((rule, fw))
                            else:
                                res[req.name] = []
                                res[req.name].append((rule, fw))

        for k, v in res.iteritems():
            print k, v

        Gtk.Gtk_Main.Gtk_Main().destroy_progress_bar()
        self.result = dict(res)
        return res

def is_subset(rule, test_rule):
    """return True if rule is a subset of test_rule, false otherwise (use ROBDD)"""
    return len(synthesize(test_rule.toBDD(), Bdd.IMPL, rule.toBDD()).items) <= 2