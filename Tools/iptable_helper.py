from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Action import Action
import socket
from ROBDD.synthesis import synthesize
from ROBDD.synthesis import Bdd
import re
from Tools.ExcelToolKit import ExcelToolKit
import os
from graphviz import Digraph

with open(fname) as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
content = [x.strip() for x in content] 