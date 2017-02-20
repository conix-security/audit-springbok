#!/usr/bin/env python
# vim: ts=4:sw=4:tw=78:nowrap
""" Exemple avec Cellrenderer modifiables et activables """
import pygtk
pygtk.require("2.0")
import gtk, gobject

taches =  {
    "Faire les courses": "Acheter une baguette",
    "Programmer": "Mettre a jour le programme",
    "Cuisiner": "Allumer le four",
    "Regarder la TV": "Enregistrer \"Urgences\""
    } 

class GUI_Controleur:
    """ La classe GUI est le controleur de l'application """
    def __init__(self):
        # Creation de la fenetre principale
        self.fenetre = gtk.Window(type=gtk.WINDOW_TOPLEVEL)
        self.fenetre.set_title("Exemple de CellRenderer")
        self.fenetre.connect("destroy", self.evnmt_destroy)
        # On recupere le modele et on le relie a la vue
        self.modele = Ranger.recup_modele()
        self.vue = Afficher.cree_vue( self.modele )
        # Ajouter la vue a la fenetre principale
        self.fenetre.add(self.vue)
        self.fenetre.show_all()
        return
    def evnmt_destroy(self, *kw):
        """ Fonction de rappel pour fermer l'application """
        gtk.main_quit()
        return
    def lance(self):
        """ La fonction est appelee pour lancer la boucle principale GTK """
        gtk.main()
        return  

class InfoModele:
    """ La classe du modele contient l'information que nous voulons afficher """
    def __init__(self):
        """ Creation et remplissage du gtk.TreeStore """
        self.tree_store = gtk.TreeStore( gobject.TYPE_STRING,
                                         gobject.TYPE_BOOLEAN )
        # on place les donnees utilisateur globales dans une liste
        # on cree une arborescence simple.
        for item in taches.keys():
            lignemere = self.tree_store.append( None, (item, None) )
            self.tree_store.append( lignemere, (taches[item],None) )
        return
    def recup_modele(self):
        """ Renvoie le modele """
        if self.tree_store:
            return self.tree_store 
        else:
            return None

class AfficheModele:
    """ Affiche le modele InfoModele dans un treeview """
    def cree_vue( self, modele ):
        """ Cree une vue pour le Tree Model """
        model = gtk.ListStore(str, str, str, str)
        model.append(("Henrik","Ibsen","green","#23abff"))
        model.append(("Samuel","Beckett","orange","OldLace"))
        model.append(("Thomas","Mann","red","peach puff"))
        treeview = gtk.TreeView(model)
        renderer = gtk.CellRendererText()
        renderer.set_property('editable', True)
        renderer.connect('edited', self.rappel_edited_col0, model)

        treeview.append_column(gtk.TreeViewColumn("First Name", renderer,
        text=0, background=2))
        treeview.append_column(gtk.TreeViewColumn("Last Name", renderer,
        text=1, background=2))
        return treeview

    def on_editing(self):
        pass
    def rappel_edited_col0( self, cellrenderer, chemin, nouveau_texte, modele ):
        """
        Appele quand un texte est modifie. Il inscrit le nouveau texte
        dans le modele pour qu'il puisse etre affiche correctement.
        """
        modele[chemin][2] = 'orange'
        #modele.append(modele[chemin])
        for i in modele[chemin]:
            print i

        #modele.insert_before(modele[chemin].iter, modele[chemin])
        print 'jajha'
        return
    def rappel_toggled_col1( self, cellrenderer, chemin, modele ):
        """
        Fixe l'etat du bouton a bascule sur true ou false.
        """
        modele[chemin][1] = not modele[chemin][1]
        print "Valeur de '%s'  : %s" % (modele[chemin][0], modele[chemin][1],)
        return

if __name__ == '__main__':
    Ranger = InfoModele()	
    Afficher = AfficheModele()
    monGUI = GUI_Controleur()
    monGUI.lance()