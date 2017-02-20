__author__ = 'maurice'

import networkx as nx
import matplotlib.pyplot as plt

g = nx.Graph()
h = range(9)
g.add_nodes_from(h)
g.add_node('else')

e1 = (1, 2)
e2 = (1, 3)
e3 = (2, 4)
e4 = (3, 4)
e5 = (4, 6)
e6 = (4, 7)
e7 = (6, 7)
e8 = (7, 8)
e9 = (5, 8)
e10 = (2, 5)
g.add_edge(*e1)
g.add_edge(*e2)
g.add_edge(*e3)
g.add_edge(*e4)
g.add_edge(*e5)
g.add_edge(*e6)
g.add_edge(*e7)
g.add_edge(*e8)
g.add_edge(*e9)
g.add_edge(*e10)
nx.draw(g)

#plt.show()


marks = []
S = []
res = []
tmp = []



def dfs2(g, v, t):
    global marks, S, res
    S.append(v)
    while len(S) > 0:
        v = S.pop()
        if v not in marks:
            marks.append(v)
            for son in g.neighbors(v):
                if son == t:
                    marks.append(son)
                    res.append(list(marks))
                    print marks
                    marks.pop()
                    S.pop()
                else:
                    S.append(son)

def _dfs(g, v, t, path):
    global res
    path.append(v)
    if (v == t):
        print path
        res.append(list(path))
    for son in g.neighbors(v):
        if v not in path:
            _dfs(g, son, t, path)


def __dfs(v, t):
    global res, marks, g
    for son in g.neighbors(v):
        if son == t:
            tmp = []
            for node1 in marks:
                tmp.append(node1)
            tmp.append(son)
            res.append(list(tmp))
            print tmp
        elif son not in marks:
            marks.append(son)
            __dfs(son, t)
            marks.pop()

def dfs(g, s, t):
    global marks, res, tmp
    marks.append(s)
    for son in g.neighbors(s):
        if s == t:
            res.append(marks)
            break
        if son not in marks:
            dfs(g, son, t)


marks.append(1)
__dfs(1, 8)
#_dfs(g, 2, 8, tmp)
print res


for e in g.edges():
    print e
#print S

#dfs(g, 2, 7)
#dfs(g, 2, 8)
#print marks
#print res