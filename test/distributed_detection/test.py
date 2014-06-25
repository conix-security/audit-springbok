#! /usr/bin/env python
# -*- coding: utf-8 -*-

import sys
sys.path.append("../../")

from Gtk import Gtk_Main
import Parser.Parser as Parser
import AnomalyDetection.DistributedDetection as DistributedDetection
from NetworkGraph.NetworkGraph import NetworkGraph


def test(file):
    ''' Distributed detection test.
    This function take a configuration file as parameter and :
    - clear the graph topology
    - detect the file type (Cisco Asa, Juniper, ...)
    - construct the firewall data structure
    - construct the graph topology
    - perform the distributed anomaly detection
    - return the error list
    '''
    res = ''
    NetworkGraph().clear()
    firewalls = Parser.parser(file, Parser.suppose_type(file), None)
    for fw in firewalls:
        fw.build_bdd()
        NetworkGraph().network_graph(fw)
    error_list = DistributedDetection.DistributedDetection(False).distributed_detection()
    for k, v in error_list:
        if len(v) > 0:
            res += "\n".join(v)
    return res
