__author__ = 'maurice'

# imports
import gtk
from gtk import *
import Gtk_Main
from NetworkGraph import NetworkGraph

## This function updates the firewall list
#  depending of wich ones have been checked by users.



class Gtk_FwSelect:
    """
        This class is used in case of parsing
        a config file wich contains multiple
        firewall definition. It will help
        the user to select the firewall(s)
        to import
    """
    def __init__(self):
        self.firewalls_list = []
        self.cbox_list = []

    def buildWindows(self):
        win = gtk.Window()
        win.set_title("Firewalls Selection")
        #win.connect("destroy", lambda x: iter_next())
        label1 = gtk.Label("The file you imported contains multiple firewalls.")
        label2 = gtk.Label("Wich one(s) do you wish to "
                          "import ?")
        vbox = gtk.VBox()
        vbox.add(label1)
        vbox.add(label2)
        #cbox_list = []
        launch_button = gtk.Button("Launch")
        for fw in self.firewalls_list:
            cbox = gtk.CheckButton(fw.hostname)
            cbox.connect("clicked", lambda x: on_sensitive(self.cbox_list, launch_button))
            self.cbox_list.append(cbox)
            vbox.add(cbox)
            print cbox.get_label()

        hbox1 = gtk.HBox()
        select_all_cbox = gtk.CheckButton('Select all')
        select_all_cbox.connect("clicked", lambda x: on_select_all(self.cbox_list, select_all_cbox))
        hbox1.add(select_all_cbox)
        vbox.add(hbox1)
        launch_button.connect("clicked", lambda x: on_launch(self.firewalls_list, self.cbox_list, win))
        launch_button.set_sensitive(False)
        cancel_button = gtk.Button("Cancel")
        cancel_button.connect("clicked", lambda x: on_cancel(win))
        hbox2 = gtk.HBox()
        hbox2.add(launch_button)
        hbox2.add(cancel_button)
        vbox.add(hbox2)
        win.add(vbox)
        win.set_modal(True)
        win.set_transient_for(Gtk_Main.Gtk_Main().window)
        win.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)
        win.show_all()

def on_sensitive(cbox_list, launch_button):
    setS = False
    for c in cbox_list:
        if c.get_active() == True:
            setS = True
    launch_button.set_sensitive(setS)

def on_launch(firewalls_list, cbox, win):
    """ This method only checks if the checkbox of the firewall is checked by the user,
        and import it into SpringBok
    """
    for c in cbox:
        if c.get_active() == False:
            for fw in firewalls_list:
                if fw.hostname == c.get_label():
                    firewalls_list.remove(fw)
    win.destroy()
    del cbox[:]
    for fw in firewalls_list:
        NetworkGraph.NetworkGraph().network_graph(fw)
        Gtk_Main.Gtk_Main().lateral_pane.firewalls.add_row(fw.hostname)
        Gtk_Main.Gtk_Main().lateral_pane.focus_firewall()
    Gtk_Main.Gtk_Main().draw()
    print Gtk_Main.Gtk_Main().menubar.menu_audit.is_sensitive()

    Gtk_Main.Gtk_Main().menubar.submenu_audit.set_sensitive(True)
    Gtk_Main.Gtk_Main().menubar.submenu_view.set_sensitive(True)
    Gtk_Main.Gtk_Main().menubar.submenu_view.set_sensitive(True)
    Gtk_Main.Gtk_Main().menubar.submenu_audit.set_sensitive(True)
    Gtk_Main.Gtk_Main().update_interface()
    #Gtk_Main.Gtk_Main().test()


def on_select_all(cbox_list, all):
    """This method is use to manage the case where the select all  checkbox is check,
        it then select all firewalls present in the list.
    """
    if all.get_active() == False:
        for c in cbox_list:
            c.set_active(False)
    else:
        for c in cbox_list:
            c.set_active(True)

def on_cancel(win):
    win.destroy()