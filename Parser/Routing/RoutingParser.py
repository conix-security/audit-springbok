from SpringBase.Route import Route
import netaddr
from SpringBase.Ip import Ip


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
            for line in fd:
                self.parse_iptables(line)

    def parse_iptables(self, line):
        print "parse_iptables"
