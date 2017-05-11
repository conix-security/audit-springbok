from SpringBase.Route import Route
import netaddr
from SpringBase.Ip import Ip
from SpringBase.Interface import Interface
from socket import inet_ntoa
from struct import pack

class RoutingParser:

    def __init__(self, fw, conf):
        self.full_data = []
        self.full_routes = []
        self.fw = fw
        self.conf = conf
        self.identifier = 0
        self.routes = []

    def fortigate_route_from_data(self, data):
        if len(data) == 6:
            if data[0] == "S" or data[0] == "S*":
                search_interface = None
                newIp = None
                ip1 = None
                for idx_inter, interface in enumerate(self.fw.interfaces):
                    if interface.nameif == data[5][:len(data[5])-1]:
                        search_interface = idx_inter
                        network1 = netaddr.IPNetwork(data[1])
                        newIp = Ip(int(network1.ip), int(network1.netmask))
                        ip1 = Ip(int(netaddr.IPAddress(data[4][:len(data[4]) - 1])), "255.255.255.255")
                        self.identifier += 1
                        break
                if search_interface is not None and newIp is not None and ip1 is not None:
                    new_route = Route(self.identifier,
                                      self.fw.interfaces[search_interface],
                                      newIp,
                                      newIp,
                                      ip1)
                    self.routes.append(new_route)
        else:
            return None

    def get_routes(self):
        return self.routes

    def parse_fortigate(self, line):
        data = line.split(" ")
        data = [i for i in data if i != ""]
        self.fortigate_route_from_data(data)

    def parse(self):
        filename = self.conf
        try:
            fd = open(filename, 'r')
        except:
            print 'Error while opening the routing file'

        if self.fw.type == "Fortinet FortiGate":
            for line in fd:
                self.parse_fortigate(line)

        if self.fw.type == "Iptables":
            # Work in progress
            check_type = 1
            # route linux
            if check_type == 1:
                for line in fd:
                    self.parse_iptables(line)

    def parse_iptables(self, line):
        data = line.split(" ")
        data = [i for i in data if i != ""]
        self.iptable_route_from_data(data)

    def iptable_route_from_data(self, data):
        if data[0] == "default":
            ip_route = Ip("0.0.0.0")
            mask_route = Ip("0.0.0.0", "0.0.0.0")
            interface_name = data[4]
            id = len(self.routes)
            gw = Ip(data[2])
            tmp = Route(id, interface_name, ip_route, mask_route, gw)
            self.routes.append(tmp)
        else:
            print data[0]
            if '/' in data[0]:
                ip_route = Ip(data[0].split('/')[0])
                mask_route = Ip("0.0.0.0", self.fromDec2Dotted(int(data[0].split('/')[1])))
            else:
                ip_route = Ip(data[0])
                mask_route = Ip("0.0.0.0")
            interface_name = data[2]
            iface = None
            for interface in self.fw.interfaces:
                if interface.nameif == interface_name:
                    iface = interface
                    break
            if iface is not None:
                id = len(self.routes)
                tmp = Route(id, iface, ip_route, mask_route, iface.network)
                self.routes.append(tmp)

        return self.routes

    def parse_interface(self):
        filename = self.conf
        try:
            fd = open(filename, 'r')
        except:
            print 'Error while opening the routing file'
        if self.fw.type == "Iptables":
            for line in fd:
                data = line.split(" ")
                data = [i for i in data if i != ""]
                self.parse_ifconfig(data)

    def parse_ifconfig(self, data):
        if data[0][len(data[0]) - 1] == ":":
            tmp = Interface(data[0][:len(data[0]) - 1])
            tmp.name = data[0][:len(data[0]) - 1]
            self.full_data.append(tmp)
        elif len(data) > 0:
            if data[0] == "inet":
                ip_device = None
                mask = None
                if len(data) == 6:
                    ip_device = data[1]
                    mask = data[3]
                elif len(data) == 4:
                    ip_device = data[1]
                    mask = data[3]
                if ip_device is not None and mask is not None:
                    new_ip = Ip(ip_device, mask)
                    self.full_data[len(self.full_data) - 1].network = new_ip

    def get_interface(self):
        return self.full_data

    def fromDec2Dotted(self, mask):
        bits = 0xffffffff ^ (1 << 32 - mask) - 1
        return inet_ntoa(pack('>I', bits))