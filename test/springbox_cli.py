#! /usr/bin/env python
# -*- coding: utf-8 -*-

""" Entry point of the cli program. Call Gtk_Main('no-graphic') for no interface
"""

import sys
import tempfile
import ntpath
import os
import csv

# used to redirect output #
SYS_OUT = sys.stdout
SYS_ERR = sys.stderr
DEV_NULL = open(os.devnull, 'w')


# redirect stdout stderr to /dev/null #
def redirect_null():
    sys.stdout = DEV_NULL
    sys.stderr = DEV_NULL


# reset stdout and stderr #
def redirect_standard():
    sys.stdout = SYS_OUT
    sys.stderr = SYS_ERR

redirect_null()
from Gtk import Gtk_Main
import Parser.Parser as Parser
from SpringBase.Protocol import Protocol
redirect_standard()

# Linux console color #
WHITE = '\033[37m'
BLUE = '\033[34m'
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
CYAN = '\033[36m'


# show help
def show_help():
    print 'Usage: %s [OPTION]... [FILE]' % sys.argv[0]
    print 'Parse firewall configuration files (Cisco Asa, Juniper Netscreen, Fortinet Forigate) ' \
          'and export parsed rules to csv format.'
    print 'Create a folder tree of the configuration ACL (springbok_rulesXXXXXX)'
    print ''
    print '\t-h, --help\t\tshow this help'
    print '\t-n, --no-confirm\tno confirmation on the device detected'
    print ''
    print 'Example:'
    print '%s -n cisco_example1.conf cisco_example2.conf' % sys.argv[0]


# Ask confirmation equipment and ask for new type if wrong
def confirm_type(supposed_type):
    if supposed_type:
        choice = raw_input(CYAN + 'Confirm [Y/n] : ' + WHITE)
        if choice in ('', 'Y', 'y'):
            return supposed_type
    select_list = CYAN + 'Select firewall type (' + ', '.join([i[1] for i in Parser.parser_list]) + ') : ' + WHITE
    choice = raw_input(select_list)
    for i in Parser.parser_list:
        if choice.replace(' ', '').lower() == i[1].replace(' ', '').lower():
            return i[0]
    return None


# parse file and return parsed firewall
def parse_file(file, no_confirm):
    # suppose type
    print CYAN + file + WHITE
    redirect_null()
    supposed_type = Parser.suppose_type(file)
    redirect_standard()
    if not supposed_type:
        print YELLOW + 'Detection failed\n' + WHITE
        if no_confirm:
            return None
    else:
        for i in Parser.parser_list:
            if i[0] == supposed_type:
                print GREEN + 'detected %s\n' % i[1] + WHITE
                break

    # confirm supposed type
    if not no_confirm:
        supposed_type = confirm_type(supposed_type)

    # re-ask while problems
    while not no_confirm and not supposed_type:
        print YELLOW + 'Invalid choice' + WHITE
        supposed_type = confirm_type(supposed_type)

    if not supposed_type:
        print RED + 'Critical no equipment parser found' + WHITE
        return None

    redirect_null()
    fws = Parser.parser(file, supposed_type, None)
    redirect_standard()

    return fws


# export rules of fw to the out_dir
def export_rules(fw, out_dir):
    # export operator to string
    def op_to_string(op):
        res = ", ".join([x.to_string() for x in op])
        if res == "":
            res = "ANY"
        return res

    # for each acl in acl list of the firewall
    for acl in fw.acl:
        with open(out_dir + "/rules_" + acl.name, 'ab+') as csvfile:
            rule_writer = csv.writer(csvfile, delimiter=';', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            if not acl.rules:
                rule_writer.writerow(["NO RULES"])
                continue
            for rule in acl.rules:
                proto_res = []
                port_dest_res = []

                if not rule.protocol:
                    proto_res.append("IP")
                else:
                    for op_proto in rule.protocol:
                        for proto in op_proto.get_services():
                            proto_res.append(Protocol(proto).to_string())

                if not rule.port_dest:
                    port_dest_res.append("ANY")
                else:
                    for op_port_dst in rule.port_dest:
                        port_dest_res.append(op_port_dst.to_string())

                # delete duplicate
                proto_res = list(set(proto_res))
                port_dest_res = list(set(port_dest_res))

                for proto in proto_res:
                    for port_dst in port_dest_res:
                        rule_writer.writerow([rule.identifier,
                                              rule.name,
                                              proto,
                                              op_to_string(rule.ip_source),
                                              op_to_string(rule.port_source),
                                              op_to_string(rule.ip_dest),
                                              port_dst,
                                              "permit" if rule.action else "deny"])


# main function (parse argument, launch export, ...)
def springbox_cli_main():
    no_confirm = False
    file_list = []
    fw_list = []
    argument_list = list(sys.argv)
    argument_list.pop(0)

    # no graphic mode
    Gtk_Main.Gtk_Main('no-graphic')
    # parse argument
    for i in argument_list:
        if i == '--no-confirm' or i == '-n':
            no_confirm = True
        elif i == '--help' or i == '-h':
            show_help()
            return
        else:
            if os.path.isfile(i):
                file_list.append(i)
            else:
                print RED + "%s is not a file\n" % i + WHITE

    # create firewall list
    for i in file_list:
        fws = parse_file(i, no_confirm)
        if fws:
            fw_list += fws
        else:
            print YELLOW + 'Firewall parse failed, skip ...' + WHITE

    res_folder = tempfile.mkdtemp(prefix="springbox_rules", dir="./")
    for fw in fw_list:
        fw_folder = res_folder + "/" + ntpath.basename(fw.name)
        os.mkdir(fw_folder)
        export_rules(fw, fw_folder)

    print YELLOW + 'Output folder is %s' % res_folder + WHITE


if __name__ == '__main__':
    springbox_cli_main()
