__author__ = 'maurice'


from SpringBase.Ip import Ip
from SpringBase.Protocol import Protocol
from SpringBase.Port import Port
from SpringBase.Interface import Interface
from SpringBase.Rule import Rule
from SpringBase.Operator import Operator
from SpringBase.Firewall import Firewall
from SpringBase.ACL import ACL
from SpringBase.Action import Action

class Route :
    '''
    This class is intended to contains all information about parsed routes.
    Routes are created when parsing config files

    Parameters :
        id : int -- the identifier of the route;
        if_name : string -- The name of the egress interface;
        net_ip_dst : Ip -- The IP adress of the destination network;
        net_mask : IP -- The mask of the preceding IP address;
        gw_ip : IP -- The address of the next-hop router;
        metric : int -- The administrative distance of the route. By default, it will be set to 1.
    '''

    def __init__(self, id, iface, net_ip_dst, net_mask, gw_ip, metric = 1, name=''):

        '''
        Intend to initialize the Route
        '''

        self.id = id
        if isinstance(iface, Interface) :
            self.iface = iface
        else:
            self.iface = None
        self.net_ip_dst = net_ip_dst
        self.net_mask = net_mask
        if self.net_mask:
            print 'netmask', self.net_mask.to_string()
        self.gw_ip = gw_ip
        self.metric = metric
        self.name = name

    def to_string(self):
        res = self.name if self.name else '' + ' '
        res += str(self.id) + ' '
        res += self.iface.nameif if self.iface else '' + ' '
        res += self.net_ip_dst.to_string() if self.net_ip_dst else '' + ' '
        res += self.net_mask.to_string() if self.net_mask else '' + ' '
        res += self.gw_ip.to_string() if self.gw_ip else '' + ' '
        res += str(self.metric)
        return res

    def to_bdd(self):
        pass
