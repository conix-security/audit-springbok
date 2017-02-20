#! /usr/bin/env python
# -*- coding: utf-8 -*-

import pygtk
pygtk.require("2.0")
import gtk


class Gtk_Message(object):
    """Help message enumeration"""
    NO_MESSAGE = ""
    WELCOME_MESSAGE = "Welcome on the Springbok project.\n" \
                      "Start by importing a configuration file or open an existing project.\n" \
                      "For more information of what you can do see the documentation."
    ON_IMPORT_CONF_FILE = "The parser will detect automatically the equipment you are trying to import.\n" \
                          "You can correct it by choosing another equipment."
    TOPOLOGY_MESSAGE = "This is the topology representation of the configuration files.\n" \
                       "You can interact with objects or the background using the mouse " \
                       "(right click, double click or left click)."
    ON_SHOW_RULES = "This is the rules related to this interface.\n" \
                    "They can be sorted and you can search a pattern using regex to find :\n" \
                    "- A defined object\n" \
                    "- An ip adress or a mask\n" \
                    "- A protocol or a port by its name or its value"
    ON_SHOW_CONFIGURATION = "This is the firewall configuration file.\n" \
                            "You can look into your configuration file and use the search " \
                            "option to search a pattern in the file.\n" \
                            "The file is not editable."
    ON_CLICK_NODE = "Clicking on a node enable you to see all detected interface.\n" \
                    "This show information about :\n" \
                    "- Interface name\n" \
                    "- Name\n" \
                    "- Interface network\n" \
                    "You can right click on a node for more interactions"
    ON_CLICK_EDGE = "You can see related rules to this interface if you right click or if you double click on the edge."
    ON_BACKGROUND_CLICK = "You can clear all markers and marked path\nor\n" \
                          "you can import a background image (png file only)"
    ON_CHANGE_TAB = "You can drag and drop pages of the notebook.\n" \
                    "You can also split it in two notebooks."
    ON_SELECT_RULE = "When you select a rule, you have its numerical values in the 'Details' section.\n" \
                     "This enable you to have object name resolution."
    ON_DEEP_SEARCH = "The deep search option enable you to have all corresponding rules on an anomaly.\n" \
                     "However, this option will take much longer"
    ON_INTERNAL_ANOMALY = "The internal anomaly detection detect all anomaly on each ACL individually.\n" \
                          "Click on a anomaly to have its definition."
    ON_DISTRIBUTED_ANOMALY = "The distributed anomaly detection detect all anomaly on all simple path.\n" \
                             "Click on a anomaly to have its definition."
    ON_ERROR_CONFIG = "The error config show you :\n" \
                      "- all unused objects\n" \
                      "- all unused rules"
    ON_SHOW_OBJECT = "This show you all defined objects of the firewall.\n" \
                     "It will also show all corresponding rules"
    ON_SHOW_SERVICE = "This show you all enabled services (based on port destination).\n" \
                      "It will also show all corresponding rules"
    ON_QUERY_PATH = "The query path enable you to see all path satisfying the query between the two points.\n" \
                    "Leaving a field empty will be considered as all possible value.\n" \
                    "For more information see the 'Help' section"
    ON_SELECT_QUERY_PATH = "When you select a path, it will be highlighted on the graph.\n" \
                           "You can double click a row to see corresponding rules."
    ON_IMPORT_QUERY_FILE = "You can import a file containing a multiple query to apply on the current project.\n" \
                           "It will perform each query and show the result in a new tab.\n" \
                           "For more details see the 'Help' section."
    ON_EXPORT_RESULT = "Exporting results enable you to have result as raw text format.\n" \
                       "For more details see the 'Help' section."
    ON_IMPORT_MATRIX_FLOW = "This tab allow you to edit the matrix flow before\n" \
                            "start the matrix verification"


class Gtk_HelpMessage:
    """Gtk_HelpMessage class.
    This class is used to show formated help message
    """
    def __init__(self):
        self.label = gtk.Label()
        self.eb = gtk.EventBox()
        self.eb.add(self.label)
        self.eb.modify_bg(gtk.STATE_NORMAL, gtk.gdk.color_parse("lightgray"))
        self.change_message(Gtk_Message.WELCOME_MESSAGE)

    def change_message(self, message):
        """Change message and format it to fit the help box"""
        formated_message = ""
        for line in message.split('\n'):
            count = 0
            for m in line.split(' '):
                formated_message += m + ' '
                count += len(m) + 1
                if count > 30:
                    formated_message += '\n'
                    count = 0
            if formated_message[-1] != '\n':
                formated_message += '\n'
        self.label.set_text(formated_message)

