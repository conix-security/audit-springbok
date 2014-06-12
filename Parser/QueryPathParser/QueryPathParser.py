#! /usr/bin/env python
# -*- coding: utf-8 -*-

import Parser.QueryPathParser.QueryPathYacc as query_parser
from Parser.QueryPathParser.QueryPathLex import lexer
import Gtk.Gtk_QueryPath
import Gtk.Gtk_Main


class QueryPathParser:
    """QueryPathParser class.
    This class is used to parse query path file and run query path search

    Parameters
    ----------
    - filename : string. The file to parse
    - query_list : Rule list. The list of rule to search
    - result : list. The result list.
    """
    def __init__(self, filename):
        self.filename = filename
        self.query_list = []
        self.result = []

    def parse(self):
        """Parse the file and get all rules to query"""
        try:
            fd = open(self.filename, 'r')
        except:
            return 'Error while opening the configuration file'

        query_parser.init()

        for line in fd:
            try:
                query_parser.parser.parse(line, lexer)
            except:
                return 'Error while parsing line: %s' % line

        self.query_list = query_parser.get_query()
        fd.close()

        return None

    def run(self):
        """Run the query path for each query and return the result list"""
        res = []
        Gtk.Gtk_Main.Gtk_Main().create_progress_bar("Query path import", len(self.query_list))
        for rule in self.query_list:
            try:
                Gtk.Gtk_Main.Gtk_Main().update_progress_bar(1)
                res.append((rule, Gtk.Gtk_QueryPath.run_query(rule, rule.ip_source[0].v1, rule.ip_dest[0].v1)))
            except:
                res.append((rule, 'N/A'))
        Gtk.Gtk_Main.Gtk_Main().destroy_progress_bar()
        self.result = res
        return res

