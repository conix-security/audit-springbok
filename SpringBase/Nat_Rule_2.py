__author__ = 'maurice'


from SpringBase.Rule import Rule


class Nat_Rule(Rule):

    def __init__(self, identifier, name, protocol, ip_source, port_source, ip_dest, port_dest, action,
                 translate_address, nat_type, translate_port):
        Rule.__init__(self, identifier, name, protocol, ip_source, port_source, ip_dest, port_dest, action)
        self.translate_address = translate_address
        self.translate_port = translate_port
        self.nat_type = nat_type

    def to_string(self, separator='\n'):
        """String representation of the Nat rule

        Parameters
        ----------
        separator : string (optional, default='\n'). Used to define element separator of the rule

        Return
        ------
        res : string.
        """
        res = "  id: "
        res += str(self.identifier)
        if self.name:
            res += separator + "  name: "
            res += self.name
        res += separator + "  protocol: ["
        for i in self.protocol:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  ip_source: ["
        for i in self.ip_source:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  port_source: ["
        for i in self.port_source:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  ip_dest: ["
        for i in self.ip_dest:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  port_dest: ["
        for i in self.port_dest:
            res += i.to_string()
            res += ","
        res += "]" + separator + "  type: "
        res += self.nat_type
        res += ","
        if self.nat_type == 'src' :
            res += "]" + separator + "  : nated to "
        elif self.nat_type == 'dst':
            res += "]" + separator + "  : nated from "
        res += self.translate_address
        return res