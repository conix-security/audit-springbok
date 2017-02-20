__author__ = 'maurice'

from SpringBase.Rule import Rule
class IPSec_Tunnel:
    def __init__(self, id, peer_src, peer_dst, rule, out_iface):
        self.id = id
        self.peer_src = peer_src
        self.peer_dst = peer_dst
        self.rule = rule
        self.out_iface = out_iface

    def to_string(self):
        res = ''
        res += self.id + ' \n'
        res += self.peer_src + '\n'
        res += self.peer_dst + '\n'
        res += self.rule.to_string() + '\n'
        res += self.out_iface.nameif + '\n'


