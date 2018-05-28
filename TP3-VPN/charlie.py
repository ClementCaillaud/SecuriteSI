from scapy.all import *

#Intercepter l'échange de clés

#Envoyer à Alice une fausse clé

#Envoyer à Bob une fausse clé

#Transmettre les messages d'Alice à Bob

#Transmettre les messages de Bob à Alice

def generate_key(a, g, p):
    key = (g ** a) % p
    return key

cap = 'https3.cap'
packet = rdpcap(cap)
packet.show()
for p in packet:
    if p.haslayer('Raw'):
        p.show()
        hexdump(p['Raw'].load)
        print('########################################')

