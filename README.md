# Présentation du projet

Ce projet réalisé dans le cadre de l'unité d'enseignement de services réseaux.
Celui-ci a pour but d'implémenter un analyseur réseau, en faisant usage de
la librairie "pcap".  
Le programme se doit de posséder : 3 niveaux de verbosité, le support de
fichiers `.pcap`, les filtres BPF, ainsi que le choix d'une interface pour une
analyse en temps réel.

# Compilation

Il suffit de lancer la commande `make` dans le dossier root du projet.

Pour nettoyer les différents fichiers générés, la commande `make clean` est
disponible.

# Usage

Les différents commutateurs supportés sont affichés après la compilation.

Ils sont au nombre de 5, à savoir :
* -i [interface]
* -o [fichier pcap]
* -f [filtre]
* -v [verbosité]
* -p [nbr de paquets]