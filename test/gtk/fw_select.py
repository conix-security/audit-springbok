__author__ = 'maurice'

from matplotlib import pyplot as plt
import networkx as nx
G = nx.Graph()
G.add_edge(1,2)
G.add_edge(2,3)
for v in G.nodes():
    G.node[v]['state']='X111'
G.node[1]['state']='''Y1111
dzdzdz
zdzd
yjtyj'''
G.node[2]['state']='Y1111'

for n in G.edges_iter():
    G.edge[n[0]][n[1]]['state']='X11111'
G.edge[2][3]['state']='Y'

pos = nx.spring_layout(G)

nx.draw(G, pos)
node_labels = nx.get_node_attributes(G,'state')
nx.draw_networkx_labels(G, pos, labels = node_labels, node_size=600, node_color='w', alpha=0.4, node_shape='d')
edge_labels = nx.get_edge_attributes(G,'state')
nx.draw_networkx_edge_labels(G, pos, labels = edge_labels, node_size=600, node_color='w', alpha=0.4, node_shape='d')
plt.savefig('this.png')
plt.show()

