from scapy.all import *

#-------------------------
# TROUVER LES TRAMES FTP
#-------------------------

def trouver_trames_ftp(packet):
    tabTrames = []
    for p in packet:
        if p.haslayer('TCP') and p.haslayer('Raw'):
            if p['TCP'].sport == 21 or p['TCP'].dport == 21:
                tabTrames.append(p)
    return tabTrames

#----------------------------------------------
# TROUVER USER ET PASS ET EXTRAIRE LES DONNEES
#----------------------------------------------

def isoler_identifiants(tabTrames):
    tabLogin = []
    tabMdp = []
    tabIpSrc = []
    tabIpDst = []
    
    for trame in tabTrames:
        contenu = str(trame['Raw'].load.strip()) #On supprime les caractères spéciaux du data
        if 'USER' in contenu:
            login = contenu.split()[1] #On garde le dernier mot 
            login = login[:-1] #On supprime le ' à la fin de la chaîne
            tabLogin.append(login)
            tabIpSrc.append(trame['IP'].src)
            tabIpDst.append(trame['IP'].dst)
        if 'PASS' in contenu:
            mdp = contenu.split()[1]
            mdp = mdp[:-1]
            tabMdp.append(mdp)
    return [tabLogin, tabMdp, tabIpSrc, tabIpDst]

#------------------------------------------
# ECRITURE DES RESULTATS DANS FICHIER TXT
#------------------------------------------

def ecrire_fichier_txt(data):
    login = data[0]
    mdp = data[1]
    src = data[2]
    dst = data[3]
    
    fichier = open("ftp.txt", "a")
    row = 0
    
    while row < len(login):
        fichier.write("\nIP SRC : ")
        fichier.write(src[row])
        
        fichier.write("\nIP DST : ")
        fichier.write(dst[row])
        
        fichier.write("\nUSER : ")
        fichier.write(login[row])
        
        fichier.write("\nPASS : ")
        fichier.write(mdp[row])
        
        fichier.write("\n-----------------------")
        row = row+1
    fichier.close()

#--------------------------------
# ----- PROGRAMME PRINCIPAL -----
#--------------------------------

pcapLogin = 'FTP Multiple.pcapng' #Le fichier contenant les trames
tabTrames = [] #Les trames du FTP
data = [] #Les données

#Lecture du packet
pLogin = rdpcap(pcapLogin)
#pLogin = sniff(filter="host 172.20.10.6")

#On parcours chaque trame et on garde celles sur le port 21 (FTP)
tabTrames = trouver_trames_ftp(pLogin)

#On cherche les trames contenant le login et le mdp
data = isoler_identifiants(tabTrames)

#Ecriture dans un fichier txt
ecrire_fichier_txt(data)

print("Données sauvegardés dans le fichier ftp.txt")
