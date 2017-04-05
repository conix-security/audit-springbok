#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.append("../../")

from Gtk import Gtk_Main
import Parser.Parser as Parser
import AnomalyDetection.InternalDetection as InternalDetection
import NetworkGraph.Node as Node
from SpringBase.Firewall import Firewall


def test(file):
    ''' Internal detection test.
    This function take a configuration file as parameter and :
    - detect the file type (Cisco Asa, Juniper, ...)
    - construct the firewall data structure
    - perform the internal detection
    - return the error list:
    '''
    res = ''
    type = Parser.suppose_type(file)
    if type is None:
        type = "Parser.JuniperNetscreen.JuniperNetscreenYacc"
    firewalls = Parser.parser(file, type, None)
    for fw in firewalls:
        fw.build_bdd()
        error_list = InternalDetection.InternalDetection(Node.Node(fw), True).detect_anomaly()
        for elem in error_list:
            for error in elem:
                res += error
    return res
