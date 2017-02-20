__author__ = 'maurice'




class Route_info:
    '''
        This class will contains formatted informations about routes.
        These informations should look like:
        Gateway1:
          * Network1
          * Network2
        Gateway2:
          * Network1
          * Network2
          ...
        ...

        Param :
            data : dict -- structured informations

    '''

    def __init__(self, data, iface):
        self.data = dict(data)
        self.text = ''
        self.iface = iface
        self.format_data()

    def format_data(self):
        for gw, networks in self.data.iteritems():
            self.text += 'GW : ' + gw + '\n'
            for network in networks:
                self.text += '      net : ' + network + '\n'
        print self.text