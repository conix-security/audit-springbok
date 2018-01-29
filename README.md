# Springbok project

## Dependencies

To launch the springbok project you need to have:

- python
- [networkX](http://networkx.github.io/documentation/latest/install.html)
- PyGtk
- [matplotlib](http://matplotlib.org/1.3.1/users/installing.html)
- LaTeX (for the documentation)
- reportlab
- graphviz

## Installation

```
apt-get install python-gtk2 python-networkx python-matplotlib python-reportlab python-netaddr
pip install graphviz
```

## Launch springbok project

```
python springbok.py
```

## Supported Firewall equipments

- Cisco Asa
- Juniper Netscreen
- Fortinet Fortigate
- Iptables (cf. [Using iptables](#iptables))

## CHANGELOG

v0.6:

- Add Iptables
- Implement VDOM for Fortigate
- Add generation of anonymous configuration file


## How it works

### <a name="iptables"></a>Using iptables

You can import your script configuration file or the output of the _iptables-save_ command.

In order to import iptables configuration files, you must concatenate the output of the _ifconfig_ command with your configuration file :

```
ifconfig | cat - my_iptables.conf > /tmp/out && mv /tmp/out my_iptables.conf
```

### File menu

#### Import firewall

Start to import a configuration file `File → Import configuration`.

You can select multiple files. For each file the tool will try to detect the equipment type.

Once the import finished, the tool launches the construction of ROBDD, which may decrease temporarily the performance of the tool. But don't worry, it won't block the software. In fact, the operation is launched in a thread.

#### Open project

You can open saved project `File → Open project`.

Once again, the tool launches the construction of ROBDD.


#### Save project

You can save the state of the current project `File → Save project`.


### Network topology

After importing files, the tool draws the network topology. You can interact with all elements. The elements can be moved and you can zoom in or out using your mouse scroll or the zoom bar at the bottom of the zone. The "Redraw" button redraws the topology. If you double click on an element a default action is launched.


#### Firewall

Default action:

- __Show the configuration file__ : the firewall configuration is not editable.

When you right click on a firewall a popup menu appears and you can:

- __Show the configuration file__ : the firewall configuration is not editable.
- __Add a note__ : this will display a small note on the firewall
- __Detect anomaly__ : this will launch the internal anomaly detection
- __Show configuration error__ : this will show unused objects and unbounded rules
- __Show defined object list__ : this will show the list of defined objects
- __Show enabled services__ : this will show all enable services (based on the rule destination ports)
- __Generate anonymous configuration__ : this enables you to create an anonymous configuration file
- __Remove__ : this will remove the selected firewall


#### Network

Default action:

- __Add a note__ : this will display a small note on the network

When you right click on a node a popup menu appear and you can:

- __Add a note__ : this will display a small note on the network
- __Add itinerary form this place__ : this will add the start marker on the network (see query path)
- __Add itinerary to this place__ : this will add the end marker on the network (see query path)
- __Change sensitivity__ : this enables you to change the color of the network (for faster overview)


#### Edge

Default action:

- __Show all ACLs__ : this will show all ACLs from/to this network

When you right click on an edge a popup menu appear and you can:

- __Select an ACL__ : this enables you to show an ACL from/to this network


#### Background

When you right click on the background a popup menu appear and you can:

- __Clear query path__ : this will remove marked paths and markers (see query path)
- __Choose a background image__ : this will enable you to choose a background image (png file only)


### Anomaly detection

Algorithms for detecting anomalies are based on the work of [Al-Shaer and H. Hamed](http://www.arc.uncc.edu/pubs/im03-cr.pdf) and [the FIREMAN project](http://www.cs.ucdavis.edu/~su/publications/fireman.pdf).

#### Taxonomy of anomalies

##### Internal detection

- __Masked rules__: The rule will not match any packets and action defined by the rule will never be taken.
 - __Shadowing__: The rule has been defined to accept/deny some packets which have been denied/accepted by preceding rules.
 - __Redundancy__: All the packets have been accepted/denied by preceding rules or will not take this path.
 - __Redundancy and correlation__: Part of the packets for this rule have been denied/accepted. Others are either accepted/denied or will not take this path.

- __Partially masked rules__: The rule matches some packets that have already been matched.
 - __Correlation__: Part of the packets supposed to be accepted/denied by the rule have been denied/accepted by preceding rules.
 - __Generalization__: The rule is a generalization of preceding rules since preceding rules match a subset of the current rule but have a different action.
 - __Redundant__: If preceding rules are removed, all the packets that match preceding rules can still be accepted/denied by the current rule. Therefore, preceding rules are redundant.


##### Distributed detection

- __Shadowing__: The rule is shadowed by upstream ACLs. It tries to accept some packets that are blocked on all reachable path.
- __Raised security level__: The rule probably reveals a raised security level. Certain packets might be allowed to access part of the network path but not to the end of this path.
- __Redundant__: The rule is probably a redundancy since the packets supposed to be denied will not reach this ACL anyway. However, multiple lines of defense are often encouraged in practice to increase overall security level.
- __Correlation__: The rule is probably an overlapping rule. Part of the packets intend to be accepted/denied by this rule have been denied/accepted by upstream ACLs.


#### Internal detection

You can launch the internal detection of a firewall by clicking on it `Right click → Detect anomaly`.

The internal detection will take each ACL of the firewall individually and will check for anomalies between the rules. The 'Deep search' option enables you to have all blamed rules on an anomaly. However, this option will take too much time to perform.


#### Distributed detection

You can launch the distributed detection of all firewalls by clicking on the menu `Audit → Distributed detection`.

The distributed detection will construct rooted tree for each pair of network and will check for anomalies along the path. The 'Deep search' option enables you to have all blamed rules on an anomaly. However, this option will take too much time to perform.


### Query path

#### Manual method

You can seek for a path between two networks. To start a search:

- Place the start marker on a network `Right click on a network → Itinerary from this place`
- Place the end marker on another network `Right click on a network → Itinerary to this place`

Then a popup shows up and you can specify:

- The protocol
- The ip source
- The port source
- The ip destination
- The port destination

You can leave a field empty to not take it into account.

If paths are found, you will be able to select a path in the right lateral pane.

- If you select a row, this will highlight the path on the network topology
- If you double click on a row, this will show you the concerned rules


#### Automatic method

You can import a query file to launch multiple query requests `Audit → Import query file`.

Each query must be separated with a single line of two hyphens.

The syntax is the following (if you don't want to specify a field just delete it):

```
protocol : protocol_value
ip-source : ip_value [optional_mask_value]
port-source : port_value
ip-destination : ip_value [optional_mask_value]
port-destination : port_value
```

### Exporting result

You can export result of the following tabs `Audit → Export result`:

- Internal detection
- Distributed detection
- Configuration error
- Query path (automatic version only)


## Springbox cli

The Springbox cli is a small script using springbok's module to export equipment ACL to an unified csv format.

### Launch Springbox cli

```
python springbox_cli.py [OPTION]... [FILE]
```

### Usage

```
Usage: ./springbox_cli.py [OPTION]... [FILE]
Parse firewall configuration files (Cisco Asa, JuniperNetscreen, Fortinet Forigate) and export parsed rules to csv format.
Create a folder tree of the configuration ACL (springbok_rulesXXXXXX)

	-h, --help          show this help
	-n, --no-confirm    no confirmation on the device detected

Example:
./springbox_cli.py -n cisco_example1.conf cisco_example2.conf
```
