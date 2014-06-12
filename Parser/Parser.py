#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Parser : Parse interface for firewall construction"""

import gtk
import time

# Parser list with tuple of module path, parser name and start line
parser_list = [('Parser.CiscoAsa.CiscoAsaYacc', 'Cisco Asa', 'access-list'),
               ('Parser.JuniperNetscreen.JuniperNetscreenYacc', 'Juniper Netscreen', 'set policy'),
               ('Parser.FortiGate.FortiGateYacc', 'Fortinet FortiGate', 'config firewall')]


def parser(file_name, yacc_parser, progressBar):
    """Construct the Firewall for the given file with the given parser

    Parameters
    ----------
    file_name : string. The file to parse
    yacc_parser : string. The module parser to import

    Return
    ------
    Return a new firewall corresponding to the file
    """
    # open file
    try:
        fd = open(file_name, 'r')
    except:
        print 'Error while opening the configuration file'
        return None

    # file length
    len = file_len(file_name)

    # import parser
    _parse_kit = __import__(yacc_parser, fromlist=['a'])

    # clear state and dictionary values
    _parse_kit.init(file_name)

    t0 = time.time() # start timer
    count = 0
    for line in fd:
        _parse_kit.update()
        try:
            _parse_kit.parser.parse(line, _parse_kit.lexer)
        except:
            print 'Error while parsing line: %s' % line
        count += 1
        if progressBar and count % (max(1, len / 100)) == 0:
            progressBar.set_fraction(1. * count / len)
            while gtk.events_pending():
                gtk.main_iteration_do(False)

    _parse_kit.finish()
    fd.close()

    print time.time() - t0

    return _parse_kit.get_firewall()


def file_len(fname):
    """Return the number of line in the file"""
    with open(fname) as f:
        for i, l in enumerate(f):
            pass
    return i + 1


def suppose_type(fname):
    """Try to detect the firewall type for a given file.

    Parameters
    ----------
    fname : string. The file name

    Return
    ------
    Return the yacc parser module to import.
    """
    _parse_kit = []

    # import pasers
    [_parse_kit.append(__import__(p[0], fromlist=['a'])) for p in parser_list]
    for p in _parse_kit:
        try:
            p.init(fname, True)
        except AttributeError:
            print "error : 'module' object has no attribute 'init'"

    with open(fname) as f:
        for i, l in enumerate(f):
            # test if line start with one proposed by parsers
            for j in xrange(len(parser_list)):
                if l.startswith(parser_list[j][2]):
                    try:
                        # verify by trying to parse
                        _parse_kit[j].parser.parse(l, _parse_kit[j].lexer)
                        return parser_list[j][0]
                    except:
                        pass
    return None