#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Parser : Parse interface for firewall construction"""

import gtk
import time
import re
import os

# Parser list with tuple of module path, parser name and start line regex
parser_list = [('Parser.CiscoAsa.CiscoAsaYacc', 'Cisco Asa', ['access-list']),
               ('Parser.Juniper_JunOS_11.JuniperNetscreenYacc', 'Juniper Netscreen', ['set policy.*from.*to']),
               ('Parser.FortiGate.FortiGateYacc', 'Fortinet FortiGate', ['config firewall policy']),
               ('Parser.IpTables.IpTablesParser', 'Iptables', ['iptables', 'Chain']),
               ('Parser.CheckPoint.CheckPointYacc', 'CheckPoint', ['\(\n'])]


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

    t0 = time.time()  # start timer
    count, ctr = 0, 0

    os.system("rm ../parse*")


    for line in fd:
        _parse_kit.update()
        ctr += 1
        try:
            _parse_kit.parser.parse(line, _parse_kit.lexer, debug=0)
        except:
            print 'Error while parsing line: %s' % line, ctr
            #raise SyntaxError
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
    i = 0
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
                for pattern in parser_list[j][2]:
                    if re.match(pattern, l.lstrip()):
                        try:
                            # verify by trying to parse
                            _parse_kit[j].parser.parse(l, _parse_kit[j].lexer)
                            return parser_list[j][0]
                        except:
                            pass
    return None


def generate_debug_conf(destination_file, file_name, type=None):
    """Generate a debug configuration file.
    This function stop at the lexing part to generate a file of token (used to send anonymous conf file).

    Parameters
    ----------
    destination_file : string. The output file
    file_name : string. The file to parse
    type : string (optional, default=None). The parse to use
    """
    if not type:
        type = suppose_type(file_name)

    for i in parser_list:
        if i[1] == type:
            type = i[0]

    if not type:
        raise Exception('No parser found for this file')

    try:
        fd = open(file_name, 'r')
        file_out = open(destination_file, 'w')
    except:
        raise Exception('Error while opening the configuration file')

    # import parser
    _parse_kit = __import__(type, fromlist=['a'])

    for line in fd:
        tokenize_line = ''
        _parse_kit.lexer.input(line)
        token = _parse_kit.lexer.token()
        while token:
            tokenize_line += token.type + ' '
            token = _parse_kit.lexer.token()
        file_out.write(tokenize_line + '\n')

    fd.close()
    file_out.close()
