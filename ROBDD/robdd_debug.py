#! /usr/bin/env python
# -*- coding: utf-8 -*-

import networkx as nx
import matplotlib.pyplot as plt

def debug_robdd(robdd):
    """This function is used for debug purpose. It is usefull for ROBDD representation.

    Parameters
    ----------
    robdd : the robdd to display
    """
    g = nx.DiGraph()

    g.add_node(str(True))
    g.add_node(str(False))

    for item in robdd.items:
        g.add_node(str(item[0]))
        if item[1] is not None:
            if isinstance(item[1], bool):
                g.add_edge(str(item[0]), str(item[1]), color='blue')
            else:
                g.add_edge(str(item[0]), str(robdd.items[item[1]][0]), color='blue')
        if item[2] is not None:
            if isinstance(item[2], bool):
                g.add_edge(str(item[0]), str(item[2]), color='red')
            else:
                g.add_edge(str(item[0]), str(robdd.items[item[2]][0]), color='red')

    plt.clf()
    pos = nx.graphviz_layout(g, prog='dot')
    if len(g.edges()) > 0:
        edges, colors = zip(*nx.get_edge_attributes(g, 'color').items())
        nx.draw(g, pos, edgelist=edges,edge_color=colors, arrows=False)
    else:
        nx.draw(g, pos, arrows=False)
    plt.show()
